"""Hosted deployment composition: lease, tenant, role identity and expiry stay bound."""

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock, patch

import pytest

from adapters.aws.deployment_session import (
    DeploymentRoleRegistration,
    ScopedDeploymentFactory,
    deployment_policy,
)
from tests.unit.test_built_deployment import prepared as prepared  # noqa: PLC0414

NOW = datetime(2026, 10, 30, tzinfo=UTC)


def registration(settings):
    a = settings.account_id
    return DeploymentRoleRegistration(
        a,
        settings.region,
        f"arn:aws:iam::{a}:role/sky-worker",
        f"arn:aws:iam::{a}:role/sky-deployment",
        "AROA" + "A" * 17,
        f"arn:aws:iam::{a}:policy/sky-deployment-boundary",
        f"arn:aws:cloudformation:{settings.region}:{a}:stack/sky-core/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        f"arn:aws:iam::{a}:role/sky-core-ExecutionRole-abc",
        f"arn:aws:iam::{a}:role/sky-core-InfrastructureRole-abc",
        "external-" + "a" * 32,
        (NOW + timedelta(hours=12)).isoformat(),
    )


def source_for(r):
    source = Mock()
    sts = source.client.return_value
    sts.get_caller_identity.return_value = {
        "Account": r.account_id,
        "Arn": f"arn:aws:sts::{r.account_id}:assumed-role/sky-worker/actual-task",
    }
    sts.get_role.return_value = {
        "Role": {
            "Arn": r.role_arn,
            "RoleId": r.role_id,
            "PermissionsBoundary": {"PermissionsBoundaryArn": r.boundary_arn},
        }
    }
    sts.assume_role.return_value = {
        "AssumedRoleUser": {"AssumedRoleId": r.role_id + ":bounded"},
        "Credentials": {
            "AccessKeyId": "synthetic",
            "SecretAccessKey": "synthetic",
            "SessionToken": "synthetic",
            "Expiration": NOW + timedelta(minutes=15),
        },
    }
    return source


def test_exact_operation_resources_and_no_secret_or_role_creation_permissions(prepared):
    adapter, request, _ = prepared
    r = registration(adapter.settings)
    policy, _ = deployment_policy(r, request)
    p = json.loads(policy)
    assert len(policy) <= 2048
    resources = next(s["NotResource"] for s in p["Statement"] if "NotResource" in s)
    token = request["build_id"].replace("-", "")
    assert f"arn:aws:ecs:{r.region}:{r.account_id}:service/default/sky-b-{token}" in resources
    assert not any("secret:" in x or x == "*" for x in resources)
    actions = {a for s in p["Statement"] for a in s.get("Action", [])}
    assert not actions & {"secretsmanager:GetSecretValue", "iam:CreateRole", "ecs:UpdateService"}


@pytest.mark.parametrize("change", [{"account_id": "999999999999"}, {"region": "us-east-1"}])
def test_foreign_request_never_assumes_role(prepared, change):
    adapter, request, _ = prepared
    r = registration(adapter.settings)
    source = Mock()
    factory = ScopedDeploymentFactory(adapter.settings, r, source=source, clock=lambda: NOW)
    with pytest.raises((ValueError, PermissionError)):
        factory.for_request({**request, **change}, Mock())
    source.client.assert_not_called()


@pytest.mark.parametrize("mutation", ["principal", "role_id", "boundary", "expired", "lease"])
def test_revoked_or_replaced_identity_cannot_receive_credentials(prepared, mutation):
    adapter, request, _ = prepared
    r = registration(adapter.settings)
    source = source_for(r)
    guard = Mock()
    if mutation == "principal":
        source.client.return_value.get_caller_identity.return_value["Arn"] = (
            "arn:aws:sts::" + r.account_id + ":assumed-role/foreign/task"
        )
    elif mutation == "role_id":
        source.client.return_value.get_role.return_value["Role"]["RoleId"] = "AROA" + "B" * 17
    elif mutation == "boundary":
        source.client.return_value.get_role.return_value["Role"]["PermissionsBoundary"] = {}
    elif mutation == "expired":
        r = replace(r, expires_at=(NOW - timedelta(seconds=1)).isoformat())
    else:
        guard.side_effect = PermissionError("lease revoked")
    with pytest.raises(PermissionError):
        ScopedDeploymentFactory(adapter.settings, r, source=source, clock=lambda: NOW).for_request(
            request, guard
        )
    source.client.return_value.assume_role.assert_not_called()


def test_sdk_calls_use_only_temporary_session_and_guard_metadata_family(prepared):
    adapter, request, _ = prepared
    r = registration(adapter.settings)
    source = source_for(r)
    raw = Mock()
    raw.client.side_effect = lambda name, **_: clients[name]
    clients = {name: Mock() for name in ("ecs", "cloudformation", "sts")}
    guard = Mock()
    with patch("boto3.Session", return_value=raw) as factory:
        bound = ScopedDeploymentFactory(adapter.settings, r, source=source, clock=lambda: NOW).for_request(
            request, guard
        )
    assert bound.ecs is clients["ecs"] and bound.stacks is clients["cloudformation"]
    assert factory.call_args.kwargs["aws_session_token"] == "synthetic"
    args = source.client.return_value.assume_role.call_args.kwargs
    assert args["DurationSeconds"] == 900
    tags = {t["Key"]: t["Value"] for t in args["Tags"]}
    assert tags["sky:ApplicationId"] == request["source_ref"]["application_id"]
    metadata = next(
        c.args[1]
        for c in clients["ecs"].meta.events.register.call_args_list
        if c.args[0] == "before-parameter-build.ecs.DescribeTaskDefinition"
    )
    with pytest.raises(PermissionError, match="another deployment"):
        metadata(
            {"taskDefinition": "arn:aws:ecs:" + r.region + ":" + r.account_id + ":task-definition/foreign:1"}
        )
    cb = next(
        c.args[1]
        for c in clients["ecs"].meta.events.register.call_args_list
        if c.args[0] == "before-call.*.*"
    )
    guard.side_effect = PermissionError("revoked")
    with pytest.raises(PermissionError, match="revoked"):
        cb()


def test_missing_registration_has_no_fallback():
    with pytest.raises(ValueError):
        DeploymentRoleRegistration.load(None)


def test_factory_adapter_cannot_retire_foreign_owner(prepared):
    adapter, request, result = prepared
    intent = adapter.prepare(request, result)
    adapter.ecs.describe_express_gateway_service.side_effect = None
    adapter.ecs.describe_express_gateway_service.return_value = {
        "service": {"serviceArn": intent["service_arn"], "tags": []}
    }
    with pytest.raises(PermissionError):
        adapter.retire(intent)
    adapter.ecs.delete_express_gateway_service.assert_not_called()


def test_database_task_inventory_permission_is_read_only_and_cluster_bounded(prepared):
    adapter, request, _ = prepared
    r = registration(adapter.settings)
    text, _ = deployment_policy(
        r, request, database_role=f"arn:aws:iam::{r.account_id}:role/sky-workload-{request['job_id']}"
    )
    assert len(text) <= 2048
    policy = json.loads(text)
    inventory = next(s for s in policy["Statement"] if s.get("Action") == ["ecs:ListTasks"])
    assert inventory["Condition"] == {
        "ArnEquals": {"ecs:cluster": f"arn:aws:ecs:{r.region}:{r.account_id}:cluster/default"}
    }
    with pytest.raises(PermissionError):
        deployment_policy(
            r, request, database_role=f"arn:aws:iam::{r.account_id}:role/sky-workload-ffffffffffffffff"
        )
