from copy import deepcopy
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import UUID

import pytest

from adapters.aws.credential_executor import AwsCredentialExecutorObserver
from application.credential_executor_inspection import CredentialExecutorInspection
from application.incident_credential_preparation import FIELD, preparation_record_is_valid
from domain.access import Role
from ports.preparation_executor import EcsPreparationExecutor
from ports.state import RecordConflict
from tests.unit.test_deployment_writes import principal
from tests.unit.test_incident_credential_preparation import setup
from tests.unit.test_operating_review import ID, NOW

pytest_plugins = ["tests.unit.test_operating_review", "tests.unit.test_security_hold_cli"]
TASK = "arn:aws:ecs:ap-northeast-2:111111111111:task/worker/" + "a" * 32
STAMP = datetime.fromisoformat(NOW)


def native():
    clients = {
        name: Mock(spec=["meta", "describe_tasks"] if name == "ecs" else ["meta", "get_caller_identity"])
        for name in ("ecs", "sts")
    }
    for client in clients.values():
        client.meta = SimpleNamespace(region_name="ap-northeast-2")
    clients["sts"].get_caller_identity.return_value = {"Account": "111111111111"}
    task = {
        "taskArn": TASK,
        "clusterArn": "arn:aws:ecs:ap-northeast-2:111111111111:cluster/worker",
        "lastStatus": "STOPPED",
        "desiredStatus": "STOPPED",
        "stoppedAt": STAMP,
        "containers": [{"taskArn": TASK, "lastStatus": "STOPPED"}],
    }
    clients["ecs"].describe_tasks.return_value = {"tasks": [task], "failures": []}
    adapter = AwsCredentialExecutorObserver(
        session=Mock(client=lambda name, **kw: clients[name]), clock=lambda: STAMP
    )
    return adapter, clients, task


def test_executor_identity_is_saved_before_any_secret_or_password_change(operating_review_setup):
    records, actor, _, adapter, service, args = setup(operating_review_setup)
    service.executor = EcsPreparationExecutor(TASK)
    mutate = adapter.prepare.side_effect

    def prepare(operation_id, *, guard):
        stored = records.job[FIELD]
        assert stored["executor"] == EcsPreparationExecutor(TASK).record(
            actor.user_id, str(UUID(operation_id))
        )
        assert stored["schema_version"] == 2 and stored["phase"] == "applying"
        return mutate(operation_id, guard=guard)

    adapter.prepare.side_effect = prepare
    result = service.prepare(actor, ID, **args)
    assert preparation_record_is_valid(result)
    # A duplicate invocation from another task returns the original identity and
    # cannot backfill, transfer execution ownership, or repeat the mutation.
    service.executor = EcsPreparationExecutor(TASK.replace("a" * 32, "b" * 32))
    assert service.prepare(actor, ID, **args) == result and adapter.prepare.call_count == 1


@pytest.mark.parametrize("change", ["account", "owner", "attempt", "extra"])
def test_wrong_executor_binding_invalidates_the_entire_preparation_record(operating_review_setup, change):
    _, actor, _, _, service, args = setup(operating_review_setup)
    service.executor = EcsPreparationExecutor(TASK)
    record = service.prepare(actor, ID, **args)
    if change == "account":
        record["executor"]["task_arn"] = TASK.replace("111111111111", "222222222222")
    elif change == "owner":
        record["executor"]["worker_owner"] = "foreign"
    elif change == "attempt":
        record["executor"]["attempt_id"] = "f" * 8 + "-ffff-ffff-ffff-" + "f" * 12
    else:
        record["executor"]["pid"] = 123
    assert not preparation_record_is_valid(record)


def test_legacy_records_remain_valid_without_manufacturing_an_executor(operating_review_setup):
    _, actor, _, _, service, args = setup(operating_review_setup)
    record = service.prepare(actor, ID, **args)
    assert record["schema_version"] == 2 and record["executor"] is None
    record.pop("executor")
    record["schema_version"] = 1
    assert preparation_record_is_valid(record)


def test_native_task_stop_is_not_provider_settlement_or_recovery_authorization():
    adapter, clients, _ = native()
    executor = EcsPreparationExecutor(TASK).record("admin", "a" * 8 + "-aaaa-aaaa-aaaa-" + "a" * 12)
    result = adapter.observe(
        executor, account_id="111111111111", region="ap-northeast-2", requested_at=NOW, guard=lambda: None
    )
    assert result["executor_state"] == "stopped" and result["read_only"] is True
    assert all(
        result[k] is False
        for k in (
            "provider_requests_settled",
            "execution_exclusion_verified",
            "recovery_authorized",
            "state_changed",
        )
    )
    assert [c[0] for c in clients["ecs"].method_calls] == ["describe_tasks"]


@pytest.mark.parametrize("change", ["running", "draining", "missing", "empty"])
def test_nonterminal_or_missing_tasks_are_never_stopped_evidence(change):
    adapter, clients, task = native()
    if change == "running":
        task.update(lastStatus="RUNNING", desiredStatus="RUNNING")
    elif change == "draining":
        task["lastStatus"] = "DEACTIVATING"
    elif change == "missing":
        clients["ecs"].describe_tasks.return_value = {
            "tasks": [],
            "failures": [{"arn": TASK, "reason": "MISSING"}],
        }
    else:
        clients["ecs"].describe_tasks.return_value = {"tasks": []}
    result = adapter.observe(
        EcsPreparationExecutor(TASK).record("admin", "a" * 8 + "-aaaa-aaaa-aaaa-" + "a" * 12),
        account_id="111111111111",
        region="ap-northeast-2",
        requested_at=NOW,
        guard=lambda: None,
    )
    assert result["executor_state"] in {"not_stopped", "unavailable"} and result["stopped_at"] is None


@pytest.mark.parametrize(
    "change",
    [
        "foreign",
        "duplicate",
        "container",
        "no-container",
        "old-stop",
        "future-stop",
        "naive-stop",
        "account",
        "region",
        "failure",
    ],
)
def test_mismatched_or_incomplete_native_evidence_is_rejected(change):
    adapter, clients, task = native()
    if change == "foreign":
        task["taskArn"] = TASK.replace("a" * 32, "b" * 32)
    elif change == "duplicate":
        clients["ecs"].describe_tasks.return_value["tasks"].append(deepcopy(task))
    elif change == "container":
        task["containers"][0]["lastStatus"] = "RUNNING"
    elif change == "no-container":
        task["containers"] = []
    elif change == "old-stop":
        task["stoppedAt"] = STAMP - timedelta(seconds=1)
    elif change == "future-stop":
        task["stoppedAt"] = STAMP + timedelta(seconds=1)
    elif change == "naive-stop":
        task["stoppedAt"] = STAMP.replace(tzinfo=None)
    elif change == "account":
        clients["sts"].get_caller_identity.return_value["Account"] = "222222222222"
    elif change == "region":
        clients["ecs"].meta.region_name = "us-east-1"
    else:
        clients["ecs"].describe_tasks.return_value = {
            "tasks": [],
            "failures": [{"arn": TASK, "reason": "ACCESS_DENIED"}],
        }
    with pytest.raises(ValueError):
        adapter.observe(
            EcsPreparationExecutor(TASK).record("admin", "a" * 8 + "-aaaa-aaaa-aaaa-" + "a" * 12),
            account_id="111111111111",
            region="ap-northeast-2",
            requested_at=NOW,
            guard=lambda: None,
        )


def app(value, identified=True):
    records, actor, _, _, prepare, args = setup(value)
    if identified:
        prepare.executor = EcsPreparationExecutor(TASK)
    record = prepare.prepare(actor, ID, **args)
    adapter, clients, _ = native()
    service = CredentialExecutorInspection(records, adapter, clock=lambda: NOW, revalidate=lambda: actor)
    return (
        records,
        actor,
        service,
        {**args, "expected_operation_id": record["operation_id"], "expected_revision": records.revision},
        clients,
    )


@pytest.mark.parametrize("phase", ["applying", "needs_attention", "prepared_restricted"])
def test_observation_keeps_original_phase_hold_and_revision(operating_review_setup, phase):
    records, actor, service, args, _ = app(operating_review_setup)
    record = records.job[FIELD]
    if phase != "prepared_restricted":
        for key in (
            "candidate_secret_ref",
            "candidate_version_id",
            "prepared_at",
            "password_update_acknowledged",
            "login_enabled",
            "active_sessions",
            "authentication_verified",
            "runtime_access_granted",
        ):
            record.pop(key)
        record["phase"] = phase
        if phase == "needs_attention":
            record["failure_code"] = "outcome_unconfirmed"
    before, writes = deepcopy(records.job), records.save_calls
    result = service.inspect(actor, ID, **args)
    assert result["executor_state"] == "stopped" and result["persisted_phase"] == phase
    assert records.job == before and records.save_calls == writes
    assert result["recovery_authorized"] is False


@pytest.mark.parametrize("legacy", [True, False])
def test_no_identity_means_unknown_and_zero_native_calls(operating_review_setup, legacy):
    records, actor, service, args, clients = app(operating_review_setup, False)
    if legacy:
        records.job[FIELD].pop("executor")
        records.job[FIELD]["schema_version"] = 1
    result = service.inspect(actor, ID, **args)
    assert result["executor_state"] == "not_recorded" and result["task_arn"] is None
    assert not any(client.mock_calls for client in clients.values())


@pytest.mark.parametrize(
    "change", ["revision", "operation", "boundary", "role", "revoked", "provider-error", "race", "claim"]
)
def test_untrusted_stale_and_changed_observations_cannot_release_access(operating_review_setup, change):
    records, actor, service, args, clients = app(operating_review_setup)
    if change == "revision":
        args["expected_revision"] -= 1
    elif change == "operation":
        args["expected_operation_id"] = "f" * 32
    elif change == "boundary":
        args["expected_boundary"] = "f" * 32
    elif change == "role":
        actor = principal(role=Role.VIEWER)
    elif change == "revoked":
        service.scope.revalidate = lambda: principal(role=Role.VIEWER)
    elif change == "provider-error":
        clients["ecs"].describe_tasks.side_effect = OSError("must-not-disclose")
    elif change == "race":

        def describe(**kw):
            records.revision += 1
            return clients["ecs"].describe_tasks.return_value

        clients["ecs"].describe_tasks.side_effect = describe
    else:
        native_observe = service.observer.observe

        def forged(*a, **kw):
            return {**native_observe(*a, **kw), "provider_requests_settled": True}

        service.observer.observe = forged
    writes = records.save_calls
    with pytest.raises((ValueError, PermissionError, RecordConflict, OSError)) as error:
        service.inspect(actor, ID, **args)
    assert "must-not-disclose" not in str(error.value) and records.save_calls == writes


def test_cli_executor_configuration_check_uses_no_cloud_or_workload_pool(configured_cli, capsys):
    from interfaces.b_runtime import main
    from tests.unit.test_security_hold_cli import arguments

    with (
        patch("boto3.Session", side_effect=AssertionError("AWS")),
        patch("interfaces.security_hold.RotatingDatabaseConnection", side_effect=AssertionError("DB")),
    ):
        main(
            arguments("inspect-credential-executor")
            + [
                "--incident-id",
                "INC-1",
                "--expected-revision",
                "1",
                "--expected-boundary",
                "a" * 32,
                "--expected-operation-id",
                "b" * 32,
                "--check-config",
            ]
        )
    assert "no AWS/DB calls" in capsys.readouterr().out
