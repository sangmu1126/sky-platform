"""Explicit operator CLI -> actual PostgreSQL recovery; ECS adapter uses SDK fixtures; RDS observation is synthetic."""

import json
from datetime import datetime
from unittest.mock import Mock, patch

import pytest

from adapters.aws.preparation_executor_observation import EcsStoppedPreparationObserver
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
@pytest.mark.parametrize(
    "failure",
    [
        None,
        "unavailable",
        "registration_changed",
        "wrong_mode",
        "running_task",
        "wrong_digest",
        "definition_denied",
    ],
)
def test_recovery_cli_persists_one_attempt_or_retains_blocked_evidence(
    recovery, store, database, monkeypatch, capsys, failure
):
    _, _, blocked, _, _, worker, preparer = recovery
    _, registered, target, _ = available_authority(recovery, store)
    clients = {name: Mock() for name in ("ecs", "sts")}
    for client in clients.values():
        client.meta.region_name = "ap-northeast-2"
    clients["sts"].get_caller_identity.return_value = {"Account": "111111111111"}
    task_arn = blocked.external_intent["executor"]["task_arn"]
    cluster = registration()["cluster_arn"]
    task = {
        "taskArn": task_arn,
        "clusterArn": cluster,
        "taskDefinitionArn": registered.profile.task_definition_arn,
        "lastStatus": "STOPPED",
        "desiredStatus": "STOPPED",
        "stoppedAt": datetime.fromisoformat(NOW),
        "containers": [
            {
                "name": "worker",
                "taskArn": task_arn,
                "lastStatus": "STOPPED",
                "imageDigest": dict(registered.profile.images)["worker"],
            }
        ],
    }
    definition = {
        "taskDefinitionArn": registered.profile.task_definition_arn,
        "containerDefinitions": [
            {"name": "worker", "command": ["worker", "--mode", "dedicated-database-queue"]}
        ],
    }
    clients["ecs"].describe_tasks.return_value = {"tasks": [task], "failures": []}
    clients["ecs"].describe_task_definition.return_value = {"taskDefinition": definition}
    stopped = EcsStoppedPreparationObserver(
        cluster,
        workspace=store.workspace,
        profile=registered.profile,
        session=Mock(client=lambda name, **_: clients[name]),
        clock=lambda: datetime.fromisoformat(NOW),
    )
    if failure == "wrong_mode":
        definition["containerDefinitions"][0]["command"] = ["api"]
    elif failure == "running_task":
        task["lastStatus"] = "RUNNING"
    elif failure == "wrong_digest":
        task["containers"][0]["imageDigest"] = "sha256:" + "d" * 64
    elif failure == "definition_denied":
        clients["ecs"].describe_task_definition.side_effect = OSError("private-provider-detail")
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

    assert {call[0] for call in clients["ecs"].method_calls} <= {"describe_tasks", "describe_task_definition"}
    if failure in {"wrong_mode", "definition_denied", None}:
        clients["ecs"].describe_task_definition.assert_called_once_with(
            taskDefinition=registered.profile.task_definition_arn
        )
    if failure in {"running_task", "wrong_digest"}:
        clients["ecs"].describe_task_definition.assert_not_called()
    if failure in {"wrong_mode", "running_task", "wrong_digest", "definition_denied"}:
        target.observe.assert_not_called()
