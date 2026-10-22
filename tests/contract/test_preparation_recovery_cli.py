"""Explicit operator CLI -> actual PostgreSQL recovery; cloud observers are synthetic."""

import json
from datetime import datetime
from unittest.mock import patch

import pytest

from interfaces.b_runtime import main
from tests.contract.test_operation_store import count
from tests.contract.test_operation_store import database as database  # noqa: PLC0414
from tests.contract.test_operation_store import store as store  # noqa: PLC0414
from tests.contract.test_preparation_recovery import ECS_EXECUTOR, available_authority
from tests.contract.test_preparation_recovery import persisted as persisted  # noqa: PLC0414
from tests.contract.test_preparation_recovery import preparation as preparation  # noqa: PLC0414
from tests.contract.test_preparation_recovery import recovery as recovery  # noqa: PLC0414
from tests.unit.test_operating_review import NOW
from tests.unit.test_preparation_recovery_cli import arguments, configured_actor, registration

pytest_plugins = ["tests.unit.test_dedicated_database_admission"]


@pytest.mark.parametrize("recovery", [ECS_EXECUTOR], indirect=True)
@pytest.mark.parametrize("failure", [None, "unavailable", "registration_changed"])
def test_recovery_cli_persists_one_attempt_or_retains_blocked_evidence(
    recovery, store, database, monkeypatch, capsys, failure
):
    _, _, blocked, _, _, worker, preparer = recovery
    _, stopped, target, _ = available_authority(recovery, store)
    monkeypatch.setenv("SKY_PREPARATION_RECOVERY_JSON", json.dumps(registration()))
    if failure == "unavailable":
        target.observe.side_effect = ValueError("private-provider-detail")
    elif failure == "registration_changed":
        receipt = target.observe.return_value

        def changed_registration(_plan, *, operation_id, guard):
            guard()
            updated = registration()
            updated["profile"]["images"]["worker"] = "sha256:" + "d" * 64
            monkeypatch.setenv("SKY_PREPARATION_RECOVERY_JSON", json.dumps(updated))
            return receipt

        target.observe.side_effect = changed_registration
    args = arguments(blocked.id, blocked.attempt_id, blocked.row_version)
    with (
        configured_actor(),
        patch("boto3.Session", side_effect=AssertionError("No live cloud clients")),
        patch("interfaces.dedicated_database_recovery.RotatingDatabaseConnection", return_value=database),
        patch(
            "interfaces.dedicated_database_recovery.AwsDedicatedDatabasePreparer", return_value=target
        ) as target_factory,
        patch(
            "interfaces.dedicated_database_recovery.EcsStoppedPreparationObserver", return_value=stopped
        ) as task_factory,
        patch("interfaces.dedicated_database_recovery.datetime") as clock,
    ):
        clock.now.return_value = datetime.fromisoformat(NOW)
        if failure:
            with pytest.raises(SystemExit) as error:
                main(args)
            assert error.value.code == 1
            output = capsys.readouterr()
            assert output.out == "" and "private-provider-detail" not in output.err
            assert store.get(blocked.id) == blocked
            assert count(store, database, "mutation_scopes") == 1
            assert count(store, database, "outbox_events") == 1
        else:
            main(args)
            result = json.loads(capsys.readouterr().out)
            assert result == {
                "operation_id": blocked.id,
                "status": "queued",
                "delivery": "durable_outbox",
                "scope": "dedicated_target_preparation_only",
                "data_routing_changed": False,
            }
            queued = store.get(blocked.id)
            assert queued.attempt_id != blocked.attempt_id
            assert count(store, database, "mutation_scopes") == 1
            assert count(store, database, "outbox_events") == 2
            assert count(store, database, "operations") == 1
            with pytest.raises(SystemExit) as error:
                main(args)
            assert error.value.code == 1
            assert capsys.readouterr().out == ""
            assert store.get(blocked.id) == queued
            target_factory.assert_called_once()
            task_factory.assert_called_once()
            assert worker.execute(queued.id, queued.attempt_id)["status"] == "succeeded"
            assert count(store, database, "mutation_scopes") == 0
            assert count(store, database, "outbox_events") == 2
    preparer.prepare.assert_called_once()  # Only the original uncertain request.
