"""Lost recovery stdout -> read-only SQL status, without replaying provider work."""

import json
from datetime import datetime
from unittest.mock import patch

import pytest

from domain.access import Role
from interfaces.b_runtime import main
from interfaces.preparation_recovery_status import recovery_status
from tests.contract.test_operation_store import count
from tests.contract.test_operation_store import database as database  # noqa: PLC0414
from tests.contract.test_operation_store import store as store  # noqa: PLC0414
from tests.contract.test_preparation_recovery import ECS_EXECUTOR, available_authority
from tests.contract.test_preparation_recovery import persisted as persisted  # noqa: PLC0414
from tests.contract.test_preparation_recovery import preparation as preparation  # noqa: PLC0414
from tests.contract.test_preparation_recovery import recovery as recovery  # noqa: PLC0414
from tests.unit.test_deployment_writes import principal
from tests.unit.test_operating_review import NOW
from tests.unit.test_preparation_recovery_cli import arguments, configured_actor, registration
from tests.unit.test_preparation_recovery_status import status_actor, status_arguments

pytest_plugins = ["tests.unit.test_dedicated_database_admission"]


def counts(store, database):
    return tuple(
        count(store, database, table)
        for table in ("operations", "mutation_scopes", "operation_events", "outbox_events")
    )


@pytest.mark.parametrize("recovery", [ECS_EXECUTOR], indirect=True)
def test_lost_recovery_response_is_confirmed_by_read_only_cli_after_registration_removed(
    recovery, store, database, monkeypatch, capsys
):
    _, _, blocked, _, _, worker, preparer = recovery
    _, stopped, target, _ = available_authority(recovery, store)
    monkeypatch.setenv("SKY_PREPARATION_RECOVERY_JSON", json.dumps(registration()))
    args = arguments(blocked.id, blocked.attempt_id, blocked.row_version)
    with (
        configured_actor(),
        patch("boto3.Session", side_effect=AssertionError("No live clients")),
        patch("interfaces.dedicated_database_recovery.RotatingDatabaseConnection", return_value=database),
        patch("interfaces.dedicated_database_recovery.AwsDedicatedDatabasePreparer", return_value=target),
        patch("interfaces.dedicated_database_recovery.EcsStoppedPreparationObserver", return_value=stopped),
        patch("interfaces.dedicated_database_recovery.datetime") as clock,
        patch("interfaces.dedicated_database_recovery.print", side_effect=OSError("stdout lost")),
    ):
        clock.now.return_value = datetime.fromisoformat(NOW)
        with pytest.raises(SystemExit) as error:
            main(args)
        assert error.value.code == 1 and capsys.readouterr().out == ""
    queued = store.get(blocked.id)
    assert queued.status == "queued" and queued.attempt_id != blocked.attempt_id
    monkeypatch.delenv("SKY_PREPARATION_RECOVERY_JSON")
    monkeypatch.delenv("SKY_OPERATING_REVIEW_POLICIES_JSON")
    reads = []

    def observed_status(records, operations, *args, **kwargs):
        with records.connection_factory() as connection:
            reads.append(connection.execute("SHOW transaction_read_only").fetchone()[0])
        return recovery_status(records, operations, *args, **kwargs)

    with (
        status_actor(),
        patch("boto3.Session", side_effect=AssertionError("No recovery/provider clients")),
        patch("interfaces.preparation_recovery_status.RotatingDatabaseConnection", return_value=database),
        patch("interfaces.preparation_recovery_status.recovery_status", side_effect=observed_status),
    ):
        for expected in ("queued", "succeeded"):
            before = counts(store, database)
            main(status_arguments(blocked.id, blocked.attempt_id, blocked.row_version))
            value = json.loads(capsys.readouterr().out)
            assert value["status"] == expected
            assert value["original_recovery_request"] == "recorded"
            assert value["observed_only"] is True
            assert not {"external_receipt", "command", "target_preparation", "checkpoint"} & value.keys()
            assert counts(store, database) == before
            if expected == "queued":
                assert worker.execute(queued.id, queued.attempt_id)["status"] == "succeeded"
    assert reads == ["on", "on"]
    assert count(store, database, "outbox_events") == 2
    preparer.prepare.assert_called_once()


@pytest.mark.parametrize("recovery", [ECS_EXECUTOR], indirect=True)
@pytest.mark.parametrize("actor", [principal(role=Role.VIEWER), principal(role=Role.ADMIN, org="foreign")])
def test_status_cli_denies_viewer_and_foreign_organization_without_state_changes(
    recovery, store, database, capsys, actor
):
    blocked = recovery[2]
    before = counts(store, database)
    with (
        status_actor(actor),
        patch("interfaces.preparation_recovery_status.RotatingDatabaseConnection", return_value=database),
        pytest.raises(SystemExit),
    ):
        main(status_arguments(blocked.id))
    assert capsys.readouterr().out == ""
    assert store.get(blocked.id) == blocked and counts(store, database) == before
