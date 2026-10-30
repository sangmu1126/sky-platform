"""Native data must remain pinned, bounded and distinct from automatic actions."""

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from adapters.aws.security_inventory import NativeSecurityInventory, fingerprint

ACCOUNT = "111111111111"
REGION = "ap-northeast-2"
NOW = datetime(2026, 10, 30, 12, tzinfo=UTC)


@pytest.fixture
def inventory():
    clients = {name: Mock() for name in ("sts", "iam", "ecs", "rds", "cloudwatch", "ec2", "logs")}
    clients["sts"].get_caller_identity.return_value = {"Account": ACCOUNT}
    session = Mock()
    session.client.side_effect = lambda name, **_: clients[name]
    return NativeSecurityInventory(ACCOUNT, REGION, session=session), clients


def iam_registration(clients):
    arn = f"arn:aws:iam::{ACCOUNT}:role/sky-worker"
    role = {
        "Arn": arn,
        "RoleId": "AROA" + "A" * 17,
        "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []},
    }
    clients["iam"].get_role.return_value = {"Role": role}
    clients["iam"].list_role_policies.return_value = {"PolicyNames": ["Owned"]}
    clients["iam"].list_attached_role_policies.return_value = {"AttachedPolicies": []}
    clients["iam"].get_role_policy.return_value = {"PolicyDocument": {"Statement": []}}
    return {
        "role_arn": arn,
        "role_id": role["RoleId"],
        "expected_digest": fingerprint(
            {
                "role_arn": arn,
                "role_id": role["RoleId"],
                "trust": role["AssumeRolePolicyDocument"],
                "boundary": None,
                "policies": {"inline:Owned": {"Statement": []}},
            }
        ),
    }


def test_iam_policy_change_and_role_recreation_are_native_evidence(inventory):
    monitor, clients = inventory
    registration = iam_registration(clients)
    assert monitor.observe_iam(registration, now=NOW.isoformat())["events"] == []
    clients["iam"].get_role_policy.return_value["PolicyDocument"] = {
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    }
    changed = monitor.observe_iam(registration, now=NOW.isoformat())
    assert changed["events"][0]["kind"] == "unapproved_iam_change"
    assert "Action" not in str(changed) and not changed["absence_of_compromise_proven"]
    clients["iam"].get_role.return_value["Role"]["RoleId"] = "AROA" + "B" * 17
    assert monitor.observe_iam(registration, now=NOW.isoformat())["events"]


def test_truncated_or_foreign_iam_inventory_cannot_claim_clean(inventory):
    monitor, clients = inventory
    registration = iam_registration(clients)
    clients["iam"].list_role_policies.return_value["IsTruncated"] = True
    with pytest.raises(ValueError, match="incomplete"):
        monitor.observe_iam(registration, now=NOW.isoformat())
    with pytest.raises(ValueError):
        monitor.observe_iam(
            {**registration, "role_arn": registration["role_arn"].replace(ACCOUNT, "222222222222")},
            now=NOW.isoformat(),
        )


def image_registration(clients):
    base = f"arn:aws:ecs:{REGION}:{ACCOUNT}:"
    arn = base + "service/default/sky-app"
    task = base + "task/default/" + "a" * 32
    definition = base + "task-definition/sky-app:1"
    image = f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/sky-managed@sha256:" + "b" * 64
    clients["ecs"].describe_services.return_value = {
        "services": [{"serviceArn": arn, "taskDefinition": definition}]
    }
    clients["ecs"].list_tasks.return_value = {"taskArns": [task]}
    clients["ecs"].describe_tasks.return_value = {
        "tasks": [
            {
                "taskArn": task,
                "group": "service:sky-app",
                "lastStatus": "RUNNING",
                "taskDefinitionArn": definition,
                "containers": [{"name": "Main", "image": image, "imageDigest": "sha256:" + "b" * 64}],
            }
        ]
    }
    return {"service_arn": arn, "task_definition_arn": definition, "container": "Main", "image": image}


def test_exact_running_task_image_mismatch(inventory):
    monitor, clients = inventory
    registration = image_registration(clients)
    assert monitor.observe_image(registration, now=NOW.isoformat())["events"] == []
    clients["ecs"].describe_tasks.return_value["tasks"][0]["containers"][0]["imageDigest"] = (
        "sha256:" + "c" * 64
    )
    value = monitor.observe_image(registration, now=NOW.isoformat())
    assert value["events"][0]["kind"] == "artifact_identity_mismatch"
    clients["ecs"].list_tasks.return_value = {"taskArns": []}
    assert monitor.observe_image(registration, now=NOW.isoformat())["collection_complete"] is False


@pytest.mark.parametrize("mutation", ["foreign_task", "duplicate", "truncated", "foreign_group"])
def test_untrusted_or_incomplete_task_inventory_rejected(inventory, mutation):
    monitor, clients = inventory
    registration = image_registration(clients)
    if mutation == "foreign_task":
        clients["ecs"].list_tasks.return_value["taskArns"] = [
            "arn:aws:ecs:us-east-1:222222222222:task/default/" + "a" * 32
        ]
    if mutation == "duplicate":
        clients["ecs"].list_tasks.return_value["taskArns"] *= 2
    if mutation == "truncated":
        clients["ecs"].list_tasks.return_value["nextToken"] = "more"
    if mutation == "foreign_group":
        clients["ecs"].describe_tasks.return_value["tasks"][0]["group"] = "service:foreign"
    with pytest.raises(ValueError):
        monitor.observe_image(registration, now=NOW.isoformat())


def test_capacity_is_pool_level_warning_requiring_two_recent_samples(inventory):
    monitor, clients = inventory
    registration = {
        "instance_id": "sky-pool",
        "resource_id": "db-ABC",
        "connection_threshold": 5,
        "free_storage_threshold_bytes": 1000,
    }
    clients["rds"].describe_db_instances.return_value = {
        "DBInstances": [
            {"DBInstanceArn": f"arn:aws:rds:{REGION}:{ACCOUNT}:db:sky-pool", "DbiResourceId": "db-ABC"}
        ]
    }

    def metrics(**kw):
        stat = kw["Statistics"][0]
        return {
            "Datapoints": [
                {"Timestamp": NOW - timedelta(minutes=i), stat: 6 if stat == "Maximum" else 2000}
                for i in (1, 2)
            ]
        }

    clients["cloudwatch"].get_metric_statistics.side_effect = metrics
    result = monitor.observe_capacity(registration, now=NOW.isoformat())
    assert result["events"][0]["kind"] == "database_capacity_exhausted"
    assert result["collection_complete"]
    clients["cloudwatch"].get_metric_statistics.side_effect = None
    clients["cloudwatch"].get_metric_statistics.return_value = {"Datapoints": []}
    result = monitor.observe_capacity(registration, now=NOW.isoformat())
    assert not result["collection_complete"] and not result["events"]


def flow_registration(clients):
    registration = {
        "flow_log_id": "fl-" + "a" * 17,
        "interface_id": "eni-" + "b" * 17,
        "vpc_id": "vpc-" + "c" * 17,
        "log_group": "/sky/flows",
        "allowed_destinations": ["10.0.0.0/8"],
    }
    fmt = "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}"
    clients["ec2"].describe_flow_logs.return_value = {
        "FlowLogs": [
            {
                "FlowLogId": registration["flow_log_id"],
                "ResourceId": registration["interface_id"],
                "FlowLogStatus": "ACTIVE",
                "LogDestinationType": "cloud-watch-logs",
                "LogGroupName": registration["log_group"],
                "LogFormat": fmt,
            }
        ]
    }
    clients["ec2"].describe_network_interfaces.return_value = {
        "NetworkInterfaces": [
            {"OwnerId": ACCOUNT, "VpcId": registration["vpc_id"], "PrivateIpAddress": "10.0.1.10"}
        ]
    }
    return registration


@pytest.mark.parametrize(
    "action,kind", [("ACCEPT", "forbidden_network_egress"), ("REJECT", "blocked_network_egress")]
)
def test_native_flow_accept_and_reject_have_different_authority(inventory, action, kind):
    monitor, clients = inventory
    registration = flow_registration(clients)
    record = f"2 {ACCOUNT} {registration['interface_id']} 10.0.1.10 203.0.113.9 1234 443 6 1 100 {int(NOW.timestamp()) - 60} {int(NOW.timestamp()) - 30} {action} OK"
    clients["logs"].filter_log_events.return_value = {
        "events": [{"eventId": "provider-immutable-id", "message": record}]
    }
    result = monitor.observe_flow(registration, now=NOW.isoformat())
    assert result["events"][0]["kind"] == kind
    clients["logs"].filter_log_events.return_value["events"][0]["message"] = record.replace(
        "10.0.1.10 203.0.113.9", "203.0.113.9 10.0.1.10"
    )
    assert not monitor.observe_flow(registration, now=NOW.isoformat())["events"]
    clients["ec2"].describe_flow_logs.return_value["FlowLogs"][0]["ResourceId"] = "eni-" + "f" * 17
    with pytest.raises(ValueError, match="changed"):
        monitor.observe_flow(registration, now=NOW.isoformat())


def test_account_authentication_precedes_inventory(inventory):
    monitor, clients = inventory
    clients["sts"].get_caller_identity.return_value = {"Account": "222222222222"}
    with pytest.raises(ValueError):
        monitor.observe_image({}, now=NOW.isoformat())
    clients["ecs"].describe_services.assert_not_called()
