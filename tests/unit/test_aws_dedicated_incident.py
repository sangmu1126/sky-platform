"""Actual composition with fake SDK clients; former shared RDS is never queried."""

import json
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

import pytest

from adapters.aws.dedicated_incident import AwsDedicatedIncidentDatabase, DedicatedIncidentRegistration
from domain.database import DatabaseBinding

pytest_plugins = ["tests.unit.test_aws_dedicated_database"]


def setup(prepared):
    preparer, plan, operation, clients, instance, _ = prepared
    registration = DedicatedIncidentRegistration(
        preparer.settings,
        DatabaseBinding(**plan["target"]),
        operation,
        plan["plan_id"],
        instance["DbiResourceId"],
        instance["MasterUserSecret"]["SecretArn"],
        5,
    )
    clients["sts"].get_caller_identity.return_value = {"Account": registration.binding.account_id}
    network = preparer.settings.source
    groups = [
        {"GroupId": group, "VpcId": network.vpc_id, "OwnerId": network.pool.account_id}
        for group in (preparer.settings.database_security_group, *network.allowed_client_groups)
    ]
    groups[0]["IpPermissions"] = [
        {
            "IpProtocol": "tcp",
            "FromPort": 5432,
            "ToPort": 5432,
            "UserIdGroupPairs": [
                {"GroupId": group, "UserId": network.pool.account_id}
                for group in network.allowed_client_groups
            ],
        }
    ]
    clients["ec2"].describe_security_groups.return_value = {"SecurityGroups": groups}
    clients["secretsmanager"].describe_secret.return_value = {
        "ARN": registration.admin_secret_arn,
        "OwningService": "rds",
    }
    clients["secretsmanager"].get_secret_value.return_value = {
        "ARN": registration.admin_secret_arn,
        "VersionStages": ["AWSCURRENT"],
        "SecretString": json.dumps({"username": "skyadmin", "password": "fixture-private-password"}),
    }

    def describe(DBInstanceIdentifier):
        assert DBInstanceIdentifier == registration.binding.instance_id  # No old shared-pool dependency.
        return {"DBInstances": [instance]}

    clients["rds"].describe_db_instances.side_effect = describe
    session = Mock()
    session.client.side_effect = lambda name, **kwargs: clients[name]
    connection = MagicMock()
    connection.execute.return_value.fetchone.return_value = (True,)
    connect = Mock(return_value=connection)
    adapter = AwsDedicatedIncidentDatabase(registration, session=session, connect=connect)
    state = SimpleNamespace(
        region=network.pool.region,
        host="state.example",
        secret_arn=(
            f"arn:aws:secretsmanager:{network.pool.region}:{network.pool.account_id}:secret:state-test01"
        ),
    )
    return adapter, state, clients, instance, connect


def resolve(adapter, state):
    return adapter.incident_restriction(
        adapter.registration.binding, state, guard=Mock(), connection_guard=Mock()
    )


def test_existing_target_resolution_never_provisions_or_reads_app_credentials(prepared):
    adapter, state, clients, instance, connect = setup(prepared)
    instance["MasterUserSecret"]["KmsKeyId"] = "AWS may include extra managed-secret metadata"
    with patch("adapters.database.dedicated_access.PostgresDedicatedAccess.existing_access") as lookup:
        restriction = resolve(adapter, state)
        assert restriction.binding == adapter.registration.binding
        lookup.assert_called_once()
        restriction.fence.connect()
        assert lookup.call_count == 2  # Every SQL connection revalidates the existing registration.
    assert connect.call_args.kwargs["sslmode"] == "verify-full"
    assert connect.call_args.kwargs["host"] == instance["Endpoint"]["Address"]
    assert connect.call_args.kwargs["user"] == "skyadmin"
    for call in clients["secretsmanager"].get_secret_value.call_args_list:
        assert call.kwargs["SecretId"] == adapter.registration.admin_secret_arn
    clients["secretsmanager"].create_secret.assert_not_called()
    clients["secretsmanager"].put_secret_value.assert_not_called()
    clients["rds"].create_db_instance.assert_not_called()
    clients["rds"].modify_db_instance.assert_not_called()
    clients["rds"].delete_db_instance.assert_not_called()
    clients["rds"].describe_db_subnet_groups.assert_not_called()


@pytest.mark.parametrize(
    "change",
    [
        "resource",
        "owner",
        "secret",
        "public",
        "region",
        "account",
        "state-endpoint",
        "state-secret",
        "pending",
        "network",
    ],
)
def test_wrong_or_changed_registration_denied_before_credentials_or_sql(prepared, change):
    adapter, state, clients, instance, connect = setup(prepared)
    if change == "resource":
        instance["DbiResourceId"] = "db-REPLACED"
    elif change == "owner":
        clients["rds"].list_tags_for_resource.return_value["TagList"][0]["Value"] = "false"
    elif change == "secret":
        instance["MasterUserSecret"]["SecretArn"] = "foreign"
    elif change == "public":
        instance["PubliclyAccessible"] = True
    elif change == "region":
        clients["ec2"].meta.region_name = "us-east-1"
    elif change == "account":
        clients["sts"].get_caller_identity.return_value = {"Account": "222222222222"}
    elif change == "state-endpoint":
        state.host = instance["Endpoint"]["Address"].upper() + "."
    elif change == "state-secret":
        state.secret_arn = adapter.registration.admin_secret_arn
    elif change == "pending":
        instance["PendingModifiedValues"] = {"DBInstanceClass": "db.t4g.large"}
    else:
        clients["ec2"].describe_security_groups.return_value["SecurityGroups"][0]["IpPermissions"][0][
            "IpRanges"
        ] = [{"CidrIp": "0.0.0.0/0"}]
    with pytest.raises(ValueError):
        resolve(adapter, state)
    connect.assert_not_called()
    clients["secretsmanager"].get_secret_value.assert_not_called()


def test_binding_mismatch_and_revoked_membership_never_reach_aws(prepared):
    adapter, state, clients, _, connect = setup(prepared)
    with pytest.raises(ValueError):
        adapter.incident_restriction(
            replace(adapter.registration.binding, application_id="foreign"),
            state,
            guard=Mock(),
            connection_guard=Mock(),
        )
    clients["sts"].get_caller_identity.assert_not_called()
    with patch("adapters.database.dedicated_access.PostgresDedicatedAccess.existing_access"):
        guard = Mock()
        restriction = adapter.incident_restriction(
            adapter.registration.binding, state, guard=Mock(), connection_guard=guard
        )
    calls = clients["rds"].describe_db_instances.call_count
    guard.side_effect = PermissionError("Membership revoked")
    with pytest.raises(PermissionError):
        restriction.fence.connect()
    assert clients["rds"].describe_db_instances.call_count == calls
    connect.assert_not_called()


@pytest.mark.parametrize(
    "field,value",
    [
        ("operation_id", "not-an-operation"),
        ("plan_id", "arbitrary"),
        ("resource_id", "arbitrary"),
        ("connection_limit", True),
        ("connection_limit", 0),
        ("admin_secret_arn", "foreign"),
    ],
)
def test_invalid_registration_is_rejected_without_clients(prepared, field, value):
    adapter, *_ = setup(prepared)
    with pytest.raises((ValueError, TypeError)):
        replace(adapter.registration, **{field: value})
