"""Cross-environment transport cannot widen legacy review/execution authority."""

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from adapters.database.environment_transfer import PostgresEnvironmentTransfer, RegisteredTransferEndpoint
from adapters.database.migration_inventory import PostgresInventoryRegistration
from domain.database_inventory import DatabaseResourceEvidence
from domain.database_migration import DatabaseLocation, DatabasePlacement, MigrationSafetyPolicy
from domain.database_transfer import RegisteredDatabaseTransfer

NOW = datetime(2026, 10, 30, 14, tzinfo=UTC)


def transfer():
    source = DatabasePlacement(
        "org",
        "app",
        "existing_workload",
        DatabaseLocation("aws", "rds_postgresql", "111111111111", "ap-northeast-2"),
        "source-rds",
        "app_source",
        "source-owner",
        17,
    )
    target = replace(
        source,
        location=DatabaseLocation("onprem", "vm_postgresql", "registered-vm", "lab"),
        instance_id="target-vm-db",
        database_name="app_target",
        owner_ref="target-owner",
    )
    return RegisteredDatabaseTransfer(
        "registered-route", source, target, "a" * 64, MigrationSafetyPolicy(120, 600, 86400)
    )


def adapter(tmp_path):
    spec = transfer()
    ca = tmp_path / "ca.pem"
    ca.write_text("test-ca-bytes")
    digest = hashlib.sha256(ca.read_bytes()).hexdigest()
    endpoints = tuple(
        RegisteredTransferEndpoint(
            PostgresInventoryRegistration(p, side + ".test", 5432, "admin", str(ca), digest),
            5432,
        )
        for p, side in ((spec.source, "source"), (spec.target, "target"))
    )
    verifiers = tuple(
        Mock(
            verify=Mock(
                return_value=DatabaseResourceEvidence(
                    endpoint.inventory.resource,
                    "resource-proof",
                    NOW,
                    endpoint.inventory.hostname,
                    5432,
                )
            )
        )
        for endpoint in endpoints
    )
    connects = (Mock(), Mock())
    transport = PostgresEnvironmentTransfer(spec, *endpoints, *connects, *verifiers, clock=lambda: NOW)
    return spec, transport, endpoints, verifiers, connects


def test_exact_route_identity_binds_source_target_policy_and_registration():
    spec = transfer()
    base = spec.document()
    assert base["plan_id"].startswith("DBT-") and "account_id" not in base["target"]
    variants = [
        replace(spec, registration_ref="different-registration"),
        replace(spec, source_revision="b" * 64),
        replace(spec, target=replace(spec.target, owner_ref="different-owner")),
        replace(spec, policy=replace(spec.policy, write_pause_budget_seconds=60)),
    ]
    assert len({base["plan_id"], *(item.document()["plan_id"] for item in variants)}) == 5


@pytest.mark.parametrize(
    "change",
    [
        {"organization_id": "other"},
        {"application_id": "other"},
        {"role": "sky_state"},
        {"database_name": "sky_pool_control"},
        {"postgres_major": 16},
    ],
)
def test_unsafe_placements_cannot_be_registered(change):
    spec = transfer()
    with pytest.raises(ValueError):
        replace(spec, target=replace(spec.target, **change))


@pytest.mark.parametrize(
    "policy",
    [
        MigrationSafetyPolicy(0, 600, 86400),
        MigrationSafetyPolicy(120, 600, 86400, method="cdc"),
        MigrationSafetyPolicy(120, 600, 86400, recovery_point_objective_seconds=1),
    ],
)
def test_transport_does_not_claim_cdc_zero_pause_or_lossy_recovery(policy):
    with pytest.raises(ValueError, match="write-pause"):
        replace(transfer(), policy=policy)


def test_same_provider_stays_on_its_own_registered_executor():
    spec = transfer()
    with pytest.raises(ValueError, match="only AWS and Linux VM"):
        replace(spec, target=replace(spec.target, location=spec.source.location))


def test_changed_or_raw_plan_rejected_before_resource_or_sql_reads(tmp_path):
    spec, transport, _, verifiers, connects = adapter(tmp_path)
    for invalid in (spec.document(), replace(spec, source_revision="b" * 64)):
        with pytest.raises(ValueError, match="registration changed"):
            transport.copy(invalid, guard=lambda: None)
    assert all(not verifier.verify.called for verifier in verifiers)
    assert all(not connect.called for connect in connects)


@pytest.mark.parametrize("kind", ["foreign", "expired", "future", "wrong-port"])
def test_resource_proof_is_checked_before_data_connections(tmp_path, kind):
    spec, transport, _, verifiers, connects = adapter(tmp_path)
    proof = verifiers[0].verify.return_value
    changes = {
        "foreign": {"placement": spec.target},
        "expired": {"observed_at": NOW - timedelta(seconds=60)},
        "future": {"observed_at": NOW + timedelta(seconds=1)},
        "wrong-port": {"server_port": 5433},
    }
    verifiers[0].verify.return_value = replace(proof, **changes[kind])
    with pytest.raises(ValueError, match="resource verification"):
        transport.copy(spec, guard=lambda: None)
    assert all(not connect.called for connect in connects)


def test_changed_ca_prevents_data_mutation(tmp_path):
    spec, transport, endpoints, _, connects = adapter(tmp_path)
    from pathlib import Path

    Path(endpoints[0].inventory.sslrootcert).write_text("different-ca")
    with pytest.raises(ValueError, match="CA certificate changed"):
        transport.copy(spec, guard=lambda: None)
    assert all(not connect.called for connect in connects)


def test_explicit_tunnel_preserves_real_tls_hostname_and_resource_port(tmp_path):
    _, _, endpoints, _, _ = adapter(tmp_path)
    base = endpoints[0]
    forwarded = replace(base, connect_port=35432, connect_hostaddr="127.0.0.1")
    assert forwarded.inventory.hostname == "source.test" and forwarded.inventory.port == 5432
    with pytest.raises(ValueError, match="loopback transport"):
        replace(base, connect_port=35432)
    with pytest.raises(ValueError, match="loopback tunnels"):
        replace(base, connect_hostaddr="192.0.2.1")


def test_foreign_baseline_cannot_start_refresh(tmp_path):
    spec, transport, _, _, connects = adapter(tmp_path)
    with pytest.raises(ValueError, match="transfer baseline"):
        transport.refresh(spec, expected_destination={"plan_id": "DBP-legacy"}, guard=lambda: None)
    assert all(not connect.called for connect in connects)


@pytest.mark.parametrize(
    "host,address,tunnel,valid",
    [
        ("127.0.0.1", "127.0.0.1", None, True),
        ("127.0.0.1", "127.0.0.2", None, False),
        ("source.test", "192.0.2.1", None, True),
        ("source.test", "127.0.0.1", "127.0.0.1", True),
        ("source.test", "192.0.2.1", "127.0.0.1", False),
    ],
)
def test_resolved_addresses_preserve_tls_hostname_and_explicit_tunnel_pin(
    tmp_path, host, address, tunnel, valid
):
    spec, transport, endpoints, _, _ = adapter(tmp_path)
    endpoint = replace(
        endpoints[0], inventory=replace(endpoints[0].inventory, hostname=host), connect_hostaddr=tunnel
    )
    db = Mock()
    db.info.get_parameters.return_value = {
        "host": host,
        "hostaddr": address,
        "port": "5432",
        "user": "admin",
        "dbname": spec.source.database_name,
        "sslmode": "verify-full",
        "sslrootcert": endpoint.inventory.sslrootcert,
    }
    db.pgconn.ssl_in_use = True
    db.execute.return_value.fetchone.return_value = (
        spec.source.database_name,
        "admin",
        170009,
        "UTF8",
        "C",
        "C",
    )
    db.execute.return_value.fetchall.return_value = [("plpgsql", "1.0")]
    if valid:
        assert transport._verify_connection(db, endpoint) == ("UTF8", "C", "C")
    else:
        with pytest.raises(ValueError, match="hostaddr"):
            transport._verify_connection(db, endpoint)
        db.execute.assert_not_called()
