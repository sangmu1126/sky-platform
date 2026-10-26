from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from adapters.aws.incident_runtime_retirement import AwsIncidentRuntimeRetirement
from application.incident_runtime_retirement import FIELD, IncidentRuntimeRetirement
from application.security_hold import SecurityHold
from domain.access import Role
from tests.unit.test_deployment_writes import ID, Records, principal
from tests.unit.test_incident_runtime_inspection import fixture
from tests.unit.test_operating_review import NOW


def native():
    result, service, task, _source, sts = fixture()
    ecs = Mock()
    ecs.meta = SimpleNamespace(
        region_name=result["region"], config=SimpleNamespace(retries={"total_max_attempts": 1})
    )
    ecs.describe_services.side_effect = lambda **_: {"services": [deepcopy(service)]}
    ecs.list_tasks.return_value = {"taskArns": []}
    ecs.describe_tasks.return_value = {"tasks": [task]}
    definition = {"taskDefinitionArn": result["task_definition_arn"], "status": "ACTIVE"}
    ecs.describe_task_definition.side_effect = lambda **_: {
        "taskDefinition": deepcopy(definition),
        "tags": service["tags"],
    }

    def delete(**_):
        service["status"] = "INACTIVE"
        return {"service": deepcopy(service)}

    def deregister(**_):
        definition["status"] = "INACTIVE"
        return {"taskDefinition": deepcopy(definition)}

    ecs.delete_service.side_effect = delete
    ecs.deregister_task_definition.side_effect = deregister
    return (
        AwsIncidentRuntimeRetirement(client=ecs, sts=sts, backend="ecs_standard"),
        result,
        ecs,
        service,
        definition,
        task,
    )


def test_only_owned_quiescent_runtime_is_retired_once():
    adapter, result, ecs, *_ = native()
    target = adapter.preflight(result, guard=lambda: None)
    receipt = adapter.retire(result, target, guard=lambda: None)
    assert receipt["registered_service_retired"] and receipt["registered_tasks_stopped"]
    assert not receipt["arbitrary_aws_launchers_fenced"] and not receipt["recovery_authorized"]
    ecs.delete_service.assert_called_once()
    ecs.deregister_task_definition.assert_called_once()
    adapter.inspect_retired(result, target, guard=lambda: None)
    ecs.delete_service.assert_called_once()


@pytest.mark.parametrize("change", ["running", "owner", "inactive-definition", "retry"])
def test_unsafe_runtime_does_not_issue_retirement(change):
    adapter, result, ecs, service, definition, _ = native()
    target = adapter.preflight(result, guard=lambda: None)
    if change == "running":
        service["runningCount"] = 1
    if change == "owner":
        service["tags"][0]["value"] = "false"
    if change == "inactive-definition":
        definition["status"] = "INACTIVE"
    if change == "retry":
        ecs.meta.config.retries = {"total_max_attempts": 2}
    with pytest.raises(ValueError):
        adapter.retire(result, target, guard=lambda: None)
    ecs.delete_service.assert_not_called()
    ecs.deregister_task_definition.assert_not_called()


def test_uncertain_delete_requires_observation_and_explicit_confirmation():
    adapter, result, ecs, _, _, _ = native()
    records, actor = Records(), principal(role=Role.ADMIN)
    records.job["result"] = result
    SecurityHold(records).place(actor, ID, incident_id="INC-1", reason="credential_exposure", now=NOW)
    control = Mock()
    control.inspect.return_value = {
        "sky_worker_external_intents_fenced": True,
        "registered_operation_requests_settled": True,
        "pending_inventory_complete": True,
        "pending_operation_ids": [],
    }
    service = IncidentRuntimeRetirement(
        records, control, adapter, clock=lambda: NOW, revalidate=lambda: actor
    )
    options = {
        "incident_id": "INC-1",
        "expected_boundary": records.job["security_review_boundary"]["id"],
        "expected_revision": records.revision,
    }
    original = ecs.deregister_task_definition.side_effect

    def uncertain(**kw):
        original(**kw)
        raise OSError("lost acknowledgement")

    ecs.deregister_task_definition.side_effect = uncertain
    with pytest.raises(OSError):
        service.retire(actor, ID, **options)
    assert records.job[FIELD]["phase"] == "needs_attention"
    options["expected_revision"] = records.revision
    with pytest.raises(ValueError, match="never automatic replay"):
        service.retire(actor, ID, **options)
    report = service.inspect(actor, ID, **options)
    assert report["registered_runtime_retirement_verified"] and not report["state_changed"]
    assert records.job[FIELD]["phase"] == "needs_attention"
    service.inspect(actor, ID, confirm=True, **options)
    assert records.job[FIELD]["phase"] == "retired"
    ecs.delete_service.assert_called_once()
    ecs.deregister_task_definition.assert_called_once()


def test_express_gateway_uses_its_own_delete_api():
    _, result, ecs, service, definition, _ = native()
    gateway = {
        "serviceArn": result["image_identity"]["service_arn"],
        "status": {"statusCode": "ACTIVE"},
        "tags": service["tags"],
        "activeConfigurations": [{"taskDefinitionArn": definition["taskDefinitionArn"]}],
    }
    ecs.describe_express_gateway_service.side_effect = lambda **_: {"service": deepcopy(gateway)}

    def delete(**_):
        gateway["status"]["statusCode"] = "INACTIVE"
        service["status"] = "INACTIVE"
        return {"service": deepcopy(gateway)}

    ecs.delete_express_gateway_service.side_effect = delete
    adapter = AwsIncidentRuntimeRetirement(
        client=ecs, sts=Mock(get_caller_identity=lambda: {"Account": result["account"]})
    )
    target = adapter.preflight(result, guard=lambda: None)
    adapter.retire(result, target, guard=lambda: None)
    ecs.delete_service.assert_not_called()
    ecs.delete_express_gateway_service.assert_called_once_with(
        serviceArn=result["image_identity"]["service_arn"]
    )


def test_express_configuration_mismatch_never_deletes_underlying_service():
    _, result, ecs, service, _, _ = native()
    ecs.describe_express_gateway_service.return_value = {
        "service": {
            "serviceArn": result["image_identity"]["service_arn"],
            "status": {"statusCode": "ACTIVE"},
            "tags": service["tags"],
            "activeConfigurations": [{"taskDefinitionArn": "foreign"}],
        }
    }
    adapter = AwsIncidentRuntimeRetirement(client=ecs, sts=Mock())
    with pytest.raises(ValueError, match="differs from registered"):
        adapter.preflight(result, guard=lambda: None)
    ecs.delete_service.assert_not_called()
    ecs.delete_express_gateway_service.assert_not_called()


def test_legacy_attempt_suffix_and_explicit_standard_backend_are_scope_checked():
    from domain.incident_runtime import runtime_identity

    adapter, result, ecs, service, _, _ = native()
    result["target"] = "aws-ecs-standard"
    result["owner_attempt"] += "-a1"
    service["tags"][1]["value"] = result["owner_attempt"]
    assert runtime_identity(result)
    assert adapter.preflight(result, guard=lambda: None)["backend"] == "ecs_standard"
    result["owner_attempt"] = result["owner_attempt"][:-1] + "4"
    with pytest.raises(ValueError):
        runtime_identity(result)
    ecs.delete_service.assert_not_called()
