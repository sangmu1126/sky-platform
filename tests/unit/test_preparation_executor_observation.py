"""SDK fixtures only: stopped-task evidence is not an RDS recovery authorization."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from adapters.aws.preparation_executor_observation import EcsStoppedPreparationObserver
from application.database_promotion_workflow import preparation_intent
from ports.preparation_executor import CreateOnlyPreparationProfile, EcsPreparationExecutor

pytest_plugins = ["tests.unit.test_database_promotion_workflow"]

CLUSTER = "arn:aws:ecs:ap-northeast-2:111111111111:cluster/sky-worker"
TASK = "arn:aws:ecs:ap-northeast-2:111111111111:task/sky-worker/" + "a" * 32
NOW = datetime(2026, 10, 22, tzinfo=UTC)


@pytest.fixture
def observed(flow):
    operation = flow[5]
    executor = EcsPreparationExecutor(TASK).record("original-worker", operation.attempt_id)
    operation = replace(
        operation,
        status="needs_attention",
        external_pending=True,
        external_intent=preparation_intent(operation.command["proposal"]["plan"], operation.id, executor),
    )
    clients = {name: Mock() for name in ("ecs", "sts")}
    for client in clients.values():
        client.meta.region_name = "ap-northeast-2"
    clients["sts"].get_caller_identity.return_value = {"Account": "111111111111"}
    task = {
        "taskArn": TASK,
        "clusterArn": CLUSTER,
        "lastStatus": "STOPPED",
        "desiredStatus": "STOPPED",
        "stoppedAt": NOW - timedelta(seconds=5),
        "containers": [{"lastStatus": "STOPPED", "taskArn": TASK}],
        "overrides": {"environment": "private-provider-detail"},
    }
    clients["ecs"].describe_tasks.return_value = {"tasks": [task], "failures": []}
    observer = EcsStoppedPreparationObserver(
        CLUSTER, workspace="test", session=Mock(client=lambda name, **_: clients[name]), clock=lambda: NOW
    )
    return observer, operation, clients, task


def test_original_stopped_task_returns_scoped_read_only_evidence(observed):
    observer, operation, clients, _ = observed
    result = observer.observe(operation, guard=Mock())
    assert result["operation_id"] == operation.id and result["attempt_id"] == operation.attempt_id
    assert result["operation_version"] == operation.row_version and result["workspace"] == "test"
    assert result["executor"] == operation.external_intent["executor"]
    assert result["scope"] == "ecs_executor_stopped_only"
    assert result["provider_requests_settled"] is False and result["recovery_authorized"] is False
    assert result["evidence_ref"].startswith("evidence:ecs-stopped/")
    assert "private-provider-detail" not in str(result)
    clients["ecs"].describe_tasks.assert_called_once_with(cluster=CLUSTER, tasks=[TASK])
    assert [call[0] for call in clients["ecs"].method_calls] == ["describe_tasks"]


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "failures",
        "duplicate",
        "running",
        "desired",
        "task",
        "cluster",
        "container",
        "no_containers",
        "no_time",
        "naive_time",
        "future_time",
        "denied",
    ],
)
def test_absent_wrong_or_nonterminal_task_never_proves_stopped(observed, change):
    observer, operation, clients, task = observed
    response = clients["ecs"].describe_tasks.return_value
    if change == "missing":
        response["tasks"] = []
    elif change == "failures":
        response["failures"] = [{"reason": "MISSING"}]
    elif change == "duplicate":
        response["tasks"].append(task)
    elif change == "running":
        task["lastStatus"] = "STOPPING"
    elif change == "desired":
        task["desiredStatus"] = "RUNNING"
    elif change in {"task", "cluster"}:
        task["taskArn" if change == "task" else "clusterArn"] = "foreign"
    elif change == "container":
        task["containers"][0]["lastStatus"] = "RUNNING"
    elif change == "no_containers":
        task["containers"] = []
    elif change == "no_time":
        task.pop("stoppedAt")
    elif change == "naive_time":
        task["stoppedAt"] = NOW.replace(tzinfo=None)
    elif change == "future_time":
        task["stoppedAt"] = NOW + timedelta(seconds=1)
    else:
        clients["ecs"].describe_tasks.side_effect = OSError("Access denied: private-provider-detail")
    with pytest.raises((ValueError, OSError)) as error:
        observer.observe(operation, guard=Mock())
    assert "private-provider-detail" not in str(error.value)
    assert {call[0] for call in clients["ecs"].method_calls} <= {"describe_tasks"}


@pytest.mark.parametrize("change", ["legacy", "other_cluster", "account", "region", "queued"])
def test_unbound_executor_and_foreign_caller_fail_closed(observed, change):
    observer, operation, clients, _ = observed
    if change == "legacy":
        operation.external_intent.pop("executor")
    elif change == "other_cluster":
        observer.cluster_name = "other-cluster"
    elif change == "account":
        clients["sts"].get_caller_identity.return_value = {"Account": "222222222222"}
    elif change == "region":
        clients["ecs"].meta.region_name = "us-east-1"
    else:
        operation = replace(operation, status="queued")
    with pytest.raises(ValueError):
        observer.observe(operation, guard=Mock())
    clients["ecs"].describe_tasks.assert_not_called()


@pytest.mark.parametrize("boundary", [1, 2, 3, 4])
def test_guard_loss_prevents_further_reads_or_evidence(observed, boundary):
    observer, operation, clients, _ = observed
    guard = Mock(side_effect=[None] * (boundary - 1) + [OSError("Authority lost")])
    with pytest.raises(OSError, match="Authority lost"):
        observer.observe(operation, guard=guard)
    if boundary <= 2:
        clients["ecs"].describe_tasks.assert_not_called()


@pytest.mark.parametrize("response", [None, [], {"tasks": [], "failures": {}}, {"tasks": [None]}])
def test_malformed_task_responses_are_not_evidence(observed, response):
    observer, operation, clients, _ = observed
    clients["ecs"].describe_tasks.return_value = response
    with pytest.raises(ValueError):
        observer.observe(operation, guard=Mock())


@pytest.mark.parametrize(
    "change",
    [
        None,
        "definition",
        "digest",
        "missing_digest",
        "extra_container",
        "command_override",
        "environment_override",
        "role_override",
    ],
)
def test_audited_profile_requires_exact_task_revision_and_every_image_digest(observed, change):
    observer, operation, _, task = observed
    profile = CreateOnlyPreparationProfile(
        "arn:aws:ecs:ap-northeast-2:111111111111:task-definition/sky-worker:7",
        (("worker", "sha256:" + "c" * 64),),
    )
    observer.profile = profile
    task["overrides"] = {"containerOverrides": [{"name": "worker"}]}
    task["taskDefinitionArn"] = profile.task_definition_arn
    task["containers"][0].update(name="worker", imageDigest="sha256:" + "c" * 64)
    if change == "definition":
        task["taskDefinitionArn"] = profile.task_definition_arn[:-1] + "8"
    elif change == "digest":
        task["containers"][0]["imageDigest"] = "sha256:" + "d" * 64
    elif change == "missing_digest":
        task["containers"][0].pop("imageDigest")
    elif change == "extra_container":
        task["containers"].append({"lastStatus": "STOPPED", "taskArn": TASK, "name": "sidecar"})
    elif change in {"command_override", "environment_override"}:
        task["overrides"]["containerOverrides"][0][
            "command" if change == "command_override" else "environment"
        ] = ["unreviewed"]
    elif change == "role_override":
        task["overrides"]["taskRoleArn"] = "unreviewed"
    if change:
        with pytest.raises(ValueError, match="audited create-only"):
            observer.observe(operation, guard=Mock())
    else:
        assert observer.observe(operation, guard=Mock())["execution_profile"] == profile.record()


@pytest.mark.parametrize("images", [(), (("worker", "latest"),), (("worker", "sha256:" + "a" * 64),) * 2])
def test_profile_cannot_use_empty_mutable_or_duplicate_images(images):
    with pytest.raises(ValueError):
        CreateOnlyPreparationProfile(
            "arn:aws:ecs:ap-northeast-2:111111111111:task-definition/worker:1", images
        )
