from copy import deepcopy
from unittest.mock import Mock

import pytest

from adapters.aws.source_recovery import PostgreSQLSourceRecovery, StatelessSourceRecovery
from tests.unit.test_built_deployment import prepared as prepared  # noqa: PLC0414


def test_public_source_recovery_requires_permission_and_running_image_identity(prepared):
    adapter, request, result = prepared
    runtime = StatelessSourceRecovery(adapter)
    build = {"request": request, "result": result}
    with pytest.raises(ValueError):
        runtime.preflight({}, "a" * 32, build, public_access=False, guard=lambda: None)
    plan = runtime.preflight({}, "a" * 32, build, public_access=True, guard=lambda: None)
    task = "arn:aws:ecs:ap-northeast-2:123456789012:task/default/" + "b" * 32
    td = "arn:aws:ecs:ap-northeast-2:123456789012:task-definition/test:1"
    adapter.ecs.list_tasks.return_value = {"taskArns": [task]}
    adapter.ecs.describe_tasks.return_value = {
        "tasks": [
            {
                "taskArn": task,
                "taskDefinitionArn": td,
                "lastStatus": "RUNNING",
                "desiredStatus": "RUNNING",
                "containers": [{"name": "Main", "imageDigest": result["image_digest"]}],
            }
        ]
    }
    proof = runtime._running_image(plan, {**result, "task_definition_arn": td}, lambda: None)
    assert proof["image_identity"]["status"] == "passed"
    adapter.ecs.describe_tasks.return_value["tasks"][0]["containers"][0]["imageDigest"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError):
        runtime._running_image(plan, {**result, "task_definition_arn": td}, lambda: None)


def test_postgresql_projection_does_not_mutate_or_reuse_old_image_review():
    adapter = Mock()
    adapter.r.assign_public_ip = True
    runtime = PostgreSQLSourceRecovery(adapter)
    job = {"security_artifact_review": {"binding": {"image": "old"}, "review_id": "OLD"}}
    before = deepcopy(job)
    build = {"result": {"image": "new"}}
    with pytest.raises(ValueError):
        runtime.preflight(job, "a" * 32, build, public_access=False, guard=lambda: None)
    adapter.preflight.return_value = {"image": "new"}
    runtime.preflight(job, "a" * 32, build, public_access=True, guard=lambda: None)
    assert job == before
    assert adapter.preflight.call_args.args[0]["security_artifact_review"]["binding"]["image"] == "new"
