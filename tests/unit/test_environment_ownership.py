from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

import pytest

from adapters.aws.registered_rds_inventory import RegisteredRdsInventory, RegisteredRdsInventoryVerifier
from adapters.database.environment_ownership import PostgresTransferOwnershipVerifier
from domain.database_inventory import DatabaseInventoryUnavailable
from tests.unit.test_database_transfer import NOW, adapter, transfer


def rds_verifier():
    placement = transfer().source
    spec = RegisteredRdsInventory(
        placement,
        "db-immutable",
        "registered.rds.test",
        5432,
        "vpc-12345678",
        ("sg-12345678",),
        (("sky-managed", "true"), ("sky-pool-id", "personal")),
    )
    rds = Mock(
        meta=SimpleNamespace(
            region_name="ap-northeast-2",
            endpoint_url="https://rds.ap-northeast-2.amazonaws.com",
        )
    )
    value = {
        "DBInstanceArn": "arn:aws:rds:ap-northeast-2:111111111111:db:source-rds",
        "DbiResourceId": "db-immutable",
        "DBInstanceStatus": "available",
        "Engine": "postgres",
        "EngineVersion": "17.9",
        "PubliclyAccessible": False,
        "StorageEncrypted": True,
        "DBSubnetGroup": {"VpcId": "vpc-12345678"},
        "Endpoint": {"Address": "registered.rds.test", "Port": 5432},
        "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-12345678", "Status": "active"}],
        "TagList": [{"Key": "sky-managed", "Value": "true"}, {"Key": "sky-pool-id", "Value": "personal"}],
    }
    rds.describe_db_instances.return_value = {"DBInstances": [value]}
    sts = Mock(
        meta=SimpleNamespace(
            region_name="ap-northeast-2",
            endpoint_url="https://sts.ap-northeast-2.amazonaws.com",
        )
    )
    sts.get_caller_identity.return_value = {"Account": "111111111111"}
    return RegisteredRdsInventoryVerifier(spec, sts=sts, rds=rds, clock=lambda: NOW), value


def test_instance_identity_is_not_falsely_presented_as_logical_database_ownership():
    verifier, _ = rds_verifier()
    proof = verifier.verify(verifier.registration.placement)
    assert proof.evidence_ref.startswith("RDS-") and not proof.evidence_ref.startswith("DBOWN-")
    assert proof.server_port == 5432


def test_automated_backup_is_resource_ownership_evidence_not_a_sql_readiness_claim():
    verifier, value = rds_verifier()
    original = verifier.verify(verifier.registration.placement)
    value["DBInstanceStatus"] = "backing-up"
    backing_up = verifier.verify(verifier.registration.placement)
    assert backing_up.placement == original.placement
    assert backing_up.evidence_ref != original.evidence_ref


@pytest.mark.parametrize(
    "change",
    [
        {"DbiResourceId": "db-recreated"},
        {"PubliclyAccessible": True},
        {"StorageEncrypted": False},
        {"DBInstanceStatus": "modifying"},
        {"EngineVersion": "16.8"},
        {"EngineVersion": "17.invalid"},
        {"DBSubnetGroup": {"VpcId": "vpc-87654321"}},
        {"Endpoint": {"Address": "other.rds.test", "Port": 5432}},
        {"VpcSecurityGroups": []},
        {
            "VpcSecurityGroups": [
                {
                    "VpcSecurityGroupId": "sg-12345678",
                    "Status": "active",
                    "unexpected": True,
                }
            ]
        },
        {"TagList": []},
        {
            "TagList": [
                {"Key": "sky-managed", "Value": "false"},
                {"Key": "sky-managed", "Value": "true"},
                {"Key": "sky-pool-id", "Value": "personal"},
            ]
        },
    ],
)
def test_instance_security_or_identity_drift_stops_ownership_collection(change):
    verifier, value = rds_verifier()
    value.update(change)
    with pytest.raises(DatabaseInventoryUnavailable):
        verifier.verify(verifier.registration.placement)


def test_foreign_account_region_and_placement_never_become_evidence():
    verifier, _ = rds_verifier()
    with pytest.raises(ValueError):
        verifier.verify(replace(verifier.registration.placement, application_id="other"))
    verifier.rds.describe_db_instances.assert_not_called()


def test_rds_registration_requires_canonical_tags_and_security_groups():
    verifier, _ = rds_verifier()
    with pytest.raises(ValueError, match="Canonical owned RDS tags"):
        replace(
            verifier.registration,
            required_tags=tuple(reversed(verifier.registration.required_tags)),
        )
    with pytest.raises(ValueError, match="Canonical RDS security groups"):
        replace(verifier.registration, security_groups=("sg-23456789", "sg-12345678"))
    with pytest.raises(ValueError, match="Exact existing workload RDS registration"):
        replace(
            verifier.registration,
            placement=replace(
                verifier.registration.placement,
                location=replace(verifier.registration.placement.location, location="private_region"),
            ),
        )


@pytest.mark.parametrize("response", [{}, {"DBInstances": []}, {"DBInstances": [{}, {}]}])
def test_rds_verifier_requires_one_canonical_instance_response(response):
    verifier, _ = rds_verifier()
    verifier.rds.describe_db_instances.return_value = response
    with pytest.raises(DatabaseInventoryUnavailable):
        verifier.verify(verifier.registration.placement)


@pytest.mark.parametrize("client", ["sts", "rds"])
def test_rds_verifier_rejects_custom_evidence_endpoint(client):
    verifier, _ = rds_verifier()
    verifier_client = getattr(verifier, client)
    verifier_client.meta.endpoint_url = "https://localhost.invalid"
    with pytest.raises(ValueError, match="Regional AWS RDS evidence authority"):
        RegisteredRdsInventoryVerifier(
            verifier.registration,
            sts=verifier.sts,
            rds=verifier.rds,
            clock=lambda: NOW,
        )
    verifier.sts.get_caller_identity.return_value = {"Account": "222222222222"}
    with pytest.raises(DatabaseInventoryUnavailable):
        verifier.verify(verifier.registration.placement)
    verifier.rds.describe_db_instances.assert_not_called()


@pytest.mark.parametrize("client", ["sts", "rds"])
def test_rds_verifier_rechecks_regional_authority_before_aws_calls(client):
    verifier, _ = rds_verifier()
    getattr(verifier, client).meta.endpoint_url = "https://localhost.invalid"

    with pytest.raises(DatabaseInventoryUnavailable):
        verifier.verify(verifier.registration.placement)
    verifier.sts.get_caller_identity.assert_not_called()
    verifier.rds.describe_db_instances.assert_not_called()


@pytest.mark.parametrize(
    "invalid", [None, "db_marker", "privileged", "inherits", "unbounded", "creates", "other_db"]
)
def test_logical_database_marker_and_restricted_writer_are_separate_required_checks(tmp_path, invalid):
    spec, _, endpoints, providers, _ = adapter(tmp_path)
    db = MagicMock()
    connect = MagicMock()
    connect.return_value.__enter__.return_value = db
    role = "sky_transfer_" + "a" * 20
    marker = "sky-transfer-v1:" + "b" * 64
    owner = (marker, "admin")
    facts = (marker, True, False, False, False, False, False, False, 8)
    privileges = (True, False, True, False, False)
    other = (False,)
    if invalid == "db_marker":
        owner = ("other", "admin")
    if invalid == "privileged":
        facts = (*facts[:3], True, *facts[4:])
    if invalid == "inherits":
        facts = (marker, True, True, *facts[3:])
    if invalid == "unbounded":
        facts = (*facts[:8], -1)
    if invalid == "creates":
        privileges = (True, True, True, False, False)
    if invalid == "other_db":
        other = (True,)
    db.execute.side_effect = [Mock(fetchone=Mock(return_value=v)) for v in (owner, facts, privileges, other)]
    verifier = PostgresTransferOwnershipVerifier(
        endpoints[0], providers[0], connect, writer_role=role, marker=marker, clock=lambda: NOW
    )
    with patch(
        "adapters.database.environment_ownership.PostgresEnvironmentTransfer._verify_connection"
    ) as pin:
        if invalid is not None:
            with pytest.raises(DatabaseInventoryUnavailable):
                verifier.verify(spec.source)
        else:
            proof = verifier.verify(spec.source)
            assert proof.evidence_ref.startswith("DBOWN-") and db.read_only is True
        pin.assert_called_once_with(db, endpoints[0])
    assert all(call.args[0].startswith("SELECT") for call in db.execute.call_args_list)
