from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from adapters.aws.incident_runtime import AwsIncidentRuntimeInspection
from application.incident_runtime_inspection import IncidentRuntimeInspection
from application.security_hold import require_no_security_hold
from domain.access import Role
from ports.state import RecordConflict
from tests.unit.test_deployment_writes import principal
from tests.unit.test_incident_credential_inspection import setup
from tests.unit.test_operating_review import ID, NOW

pytest_plugins = ["tests.unit.test_operating_review", "tests.unit.test_security_hold_cli"]
PREFIX = "arn:aws:ecs:ap-northeast-2:111111111111:"
ARN = PREFIX + "service/default/test"
TASK = PREFIX + "task/default/" + "a" * 32
OTHER = PREFIX + "task/default/" + "b" * 32
DEFINITION = PREFIX + "task-definition/test:1"


def fixture():
    result = {
        "target": "aws-ecs-express",
        "account": "111111111111",
        "region": "ap-northeast-2",
        "owner_attempt": "a" * 16,
        "service": "test",
        "task_definition_arn": DEFINITION,
        "image_identity": {
            "protocol": "ecs-image-identity-v1",
            "status": "passed",
            "service_arn": ARN,
            "task_definition_arn": DEFINITION,
            "task_arns": [TASK],
        },
    }
    service = {
        "serviceArn": ARN,
        "clusterArn": PREFIX + "cluster/default",
        "status": "ACTIVE",
        "taskDefinition": DEFINITION,
        "tags": [{"key": "sky-managed", "value": "true"}, {"key": "sky-attempt", "value": "a" * 16}],
        "desiredCount": 0,
        "runningCount": 0,
        "pendingCount": 0,
        "deployments": [{"desiredCount": 0, "runningCount": 0, "pendingCount": 0}],
    }
    task = {
        "taskArn": TASK,
        "taskDefinitionArn": DEFINITION,
        "clusterArn": PREFIX + "cluster/default",
        "group": "service:test",
        "lastStatus": "STOPPED",
        "desiredStatus": "STOPPED",
        "containers": [{"lastStatus": "STOPPED"}],
    }
    client = Mock(spec=["describe_services", "list_tasks", "describe_tasks", "meta"])
    client.meta = SimpleNamespace(region_name="ap-northeast-2")
    client.describe_services.return_value = {"services": [service]}
    client.list_tasks.return_value = {"taskArns": []}
    client.describe_tasks.return_value = {"tasks": [task]}
    sts = Mock(spec=["get_caller_identity"])
    sts.get_caller_identity.return_value = {"Account": "111111111111"}
    return result, service, task, client, sts


def test_native_inspection_checks_recorded_historical_tasks_even_if_lists_empty():
    result, _, _, client, sts = fixture()
    guard = Mock()
    report = AwsIncidentRuntimeInspection(client=client, sts=sts).inspect(result, guard=guard)
    assert report["registered_service_quiescent"] is True
    assert report["execution_exclusion_verified"] is False and report["scheduler_fenced"] is False
    assert report["state_changed"] is False
    assert client.describe_tasks.call_args.kwargs["tasks"] == [TASK]
    assert [call.kwargs["desiredStatus"] for call in client.list_tasks.call_args_list] == [
        "RUNNING",
        "STOPPED",
    ]
    assert guard.call_count == 12


@pytest.mark.parametrize("change", ["desired", "running", "pending", "draining", "container", "deployment"])
def test_active_or_draining_workload_is_not_quiescent(change):
    result, service, task, client, sts = fixture()
    if change in {"desired", "running", "pending"}:
        service[change + "Count"] = 1
    elif change == "draining":
        task["lastStatus"] = "DEACTIVATING"
    elif change == "container":
        task["containers"][0]["lastStatus"] = "RUNNING"
    else:
        service["deployments"][0]["runningCount"] = 1
    assert (
        AwsIncidentRuntimeInspection(client=client, sts=sts).inspect(result, guard=lambda: None)[
            "registered_service_quiescent"
        ]
        is False
    )


@pytest.mark.parametrize(
    "change",
    [
        "account",
        "region",
        "owner",
        "foreign",
        "missing",
        "truncated",
        "duplicate",
        "group",
        "negative",
        "bool",
        "definition",
        "race",
        "denied",
        "container-missing",
    ],
)
def test_native_incomplete_unowned_or_changed_observation_never_passes(change):
    result, service, task, client, sts = fixture()
    if change == "account":
        sts.get_caller_identity.return_value["Account"] = "222222222222"
    elif change == "region":
        client.meta.region_name = "us-east-1"
    elif change == "owner":
        service["tags"][1]["value"] = "foreign"
    elif change == "foreign":
        client.list_tasks.return_value = {"taskArns": [TASK.replace("default/", "foreign/")]}
    elif change == "missing":
        client.describe_tasks.return_value = {"tasks": [], "failures": [{"arn": TASK, "reason": "MISSING"}]}
    elif change == "truncated":
        client.list_tasks.return_value["nextToken"] = "next"
    elif change == "duplicate":
        client.describe_tasks.return_value["tasks"].append(deepcopy(task))
    elif change == "group":
        task["group"] = "service:foreign"
    elif change in {"negative", "bool"}:
        service["desiredCount"] = -1 if change == "negative" else False
    elif change == "definition":
        service["taskDefinition"] = DEFINITION + "2"
    elif change == "race":
        client.describe_services.side_effect = [
            {"services": [deepcopy(service)]},
            {"services": [{**service, "runningCount": 1}]},
        ]
    elif change == "denied":
        client.describe_tasks.side_effect = PermissionError("denied")
    else:
        task["containers"] = None
        # Insufficient container evidence returns a blocked observation.
        assert not AwsIncidentRuntimeInspection(client=client, sts=sts).inspect(result, guard=lambda: None)[
            "registered_service_quiescent"
        ]
        return
    with pytest.raises((ValueError, PermissionError)):
        AwsIncidentRuntimeInspection(client=client, sts=sts).inspect(result, guard=lambda: None)


def test_native_inspects_new_tasks_not_in_the_original_image_receipt():
    result, _, task, client, sts = fixture()
    client.list_tasks.return_value["taskArns"] = [OTHER]
    client.describe_tasks.return_value["tasks"].append({**task, "taskArn": OTHER, "lastStatus": "RUNNING"})
    report = AwsIncidentRuntimeInspection(client=client, sts=sts).inspect(result, guard=lambda: None)
    assert report["task_arns"] == [TASK, OTHER] and not report["registered_service_quiescent"]


@pytest.mark.parametrize("change", ["empty", "duplicate", "foreign", "bad-region", "bad-owner", "missing"])
def test_malformed_record_has_no_native_calls(change):
    result, _, _, client, sts = fixture()
    if change == "empty":
        result["image_identity"]["task_arns"] = []
    elif change == "duplicate":
        result["image_identity"]["task_arns"] *= 2
    elif change == "foreign":
        result["image_identity"]["service_arn"] = ARN.replace("111111111111", "222222222222")
    elif change == "bad-region":
        result["region"] = "foreign"
    elif change == "bad-owner":
        result["owner_attempt"] = "foreign"
    else:
        result.pop("image_identity")
    with pytest.raises(ValueError):
        AwsIncidentRuntimeInspection(client=client, sts=sts).inspect(result, guard=lambda: None)
    assert not client.mock_calls and not sts.mock_calls


def application(fixture_value):
    records, actor, _, _, args, _ = setup(fixture_value, "prepared_restricted")
    result, _, _, client, sts = fixture()
    records.job["result"] = result
    runtime = AwsIncidentRuntimeInspection(client=client, sts=sts)
    service = IncidentRuntimeInspection(records, runtime, clock=lambda: NOW, revalidate=lambda: actor)
    args.pop("expected_operation_id")
    return records, actor, service, args, client


def test_application_never_releases_hold_or_changes_preparation_even_if_stopped(operating_review_setup):
    records, actor, service, args, _ = application(operating_review_setup)
    before, calls = deepcopy(records.job), records.save_calls
    result = service.inspect(actor, ID, **args)
    assert result["registered_service_quiescent"] is True and result["recovery_authorized"] is False
    assert records.job == before and records.save_calls == calls
    with pytest.raises(ValueError):
        require_no_security_hold(records.job)


@pytest.mark.parametrize("change", ["revision", "incident", "boundary", "role", "revoked"])
def test_application_rejects_stale_or_unauthorized_request_before_native_calls(
    operating_review_setup, change
):
    _, actor, service, args, client = application(operating_review_setup)
    if change == "revision":
        args["expected_revision"] -= 1
    elif change == "incident":
        args["incident_id"] = "foreign"
    elif change == "boundary":
        args["expected_boundary"] = "f" * 32
    elif change == "role":
        actor = principal(role=Role.VIEWER)
    else:
        service.revalidate = lambda: principal(role=Role.VIEWER)
    with pytest.raises((ValueError, PermissionError, RecordConflict)):
        service.inspect(actor, ID, **args)
    assert not client.mock_calls


def test_application_detects_mid_probe_race_without_writes(operating_review_setup):
    records, actor, service, args, client = application(operating_review_setup)
    client.list_tasks.side_effect = lambda **kwargs: (
        setattr(records, "revision", records.revision + 1),
        {"taskArns": []},
    )[1]
    before = records.save_calls
    with pytest.raises(RecordConflict):
        service.inspect(actor, ID, **args)
    assert records.save_calls == before


def test_native_errors_do_not_leak_to_operator(operating_review_setup):
    _, actor, service, args, client = application(operating_review_setup)
    client.describe_tasks.side_effect = OSError("must-not-disclose")
    with pytest.raises(OSError) as error:
        service.inspect(actor, ID, **args)
    assert "must-not-disclose" not in str(error.value)


def test_runtime_cli_check_configuration_never_creates_cloud_or_db_clients(configured_cli, capsys):
    from unittest.mock import patch

    from interfaces.b_runtime import main
    from tests.unit.test_security_hold_cli import arguments

    with (
        patch("boto3.client", side_effect=AssertionError("AWS")),
        patch("interfaces.security_hold.RotatingDatabaseConnection", side_effect=AssertionError("DB")),
    ):
        main(
            arguments("inspect-runtime")
            + [
                "--incident-id",
                "INC-1",
                "--expected-revision",
                "1",
                "--expected-boundary",
                "a" * 32,
                "--check-config",
            ]
        )
    assert "no AWS/DB calls" in capsys.readouterr().out


@pytest.mark.parametrize("change", ["service", "cluster", "tasks", "exclusion", "authorized", "clock"])
def test_forged_port_receipts_cannot_expand_observation_claims(operating_review_setup, change):
    _, actor, service, args, _ = application(operating_review_setup)
    result = service.runtime.inspect(fixture()[0], guard=lambda: None)
    if change == "service":
        result["service_arn"] = "foreign"
    elif change == "cluster":
        result["cluster_arn"] = "foreign"
    elif change == "tasks":
        result["task_arns"] = []
    elif change == "exclusion":
        result["execution_exclusion_verified"] = True
    elif change == "authorized":
        result["recovery_authorized"] = True
    else:
        from datetime import datetime, timedelta

        stamps = iter([NOW, (datetime.fromisoformat(NOW) + timedelta(seconds=301)).isoformat()])
        service.clock = lambda: next(stamps)
    service.runtime = Mock(inspect=Mock(return_value=result))
    with pytest.raises(OSError):
        service.inspect(actor, ID, **args)


@pytest.mark.parametrize(
    "extra",
    [
        ["--confirm-hold"],
        ["--confirm-database-restriction"],
        ["--expected-operation-id", "b" * 32],
        ["--confirm-credential-preparation"],
        ["--confirm-false-positive"],
    ],
)
def test_runtime_cli_rejects_mutation_flags(configured_cli, extra):
    from interfaces.b_runtime import main
    from tests.unit.test_security_hold_cli import arguments

    with pytest.raises(SystemExit) as error:
        main(
            arguments("inspect-runtime")
            + [
                "--incident-id",
                "INC-1",
                "--expected-revision",
                "1",
                "--expected-boundary",
                "a" * 32,
                "--check-config",
            ]
            + extra
        )
    assert error.value.code == 2
