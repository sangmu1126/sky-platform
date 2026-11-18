"""Fresh metadata is necessary, never sufficient authority to move production data."""

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from application.database_migration_preflight import DatabaseMigrationPreflight
from domain.database_inventory import (
    DatabaseInventory,
    DatabaseInventoryUnavailable,
    DatabaseResourceEvidence,
)
from domain.database_migration import DatabaseLocation, DatabasePlacement, MigrationSafetyPolicy
from engine.database_migration import plan_database_migration

NOW = datetime(2026, 10, 30, 12, tzinfo=UTC)


@pytest.fixture
def case():
    source = DatabasePlacement(
        "org",
        "app",
        "shared_workload",
        DatabaseLocation("aws", "rds_postgresql", "111111111111", "ap-northeast-2"),
        "pool",
        "app_db",
        "source-owner",
        17,
    )
    target = replace(source, role="dedicated_workload", instance_id="dedicated", owner_ref="target-owner")
    safety = MigrationSafetyPolicy(120, 600, 86400)
    plan = plan_database_migration(source, target, safety, source_revision="a" * 64)

    def observation(placement, count):
        return DatabaseInventory(
            plan["plan_id"],
            placement,
            DatabaseResourceEvidence(placement, "audit-1", NOW, "db.example", 5432),
            NOW,
            170005,
            (("plpgsql", "1.0"),),
            count,
            "supported",
            "b" * 64,
            "UTF8",
            "C",
            "C",
        )

    readers = [
        Mock(inspect=Mock(return_value=observation(source, 1))),
        Mock(inspect=Mock(return_value=observation(target, 0))),
    ]
    return source, target, safety, readers


def inspect(case, *, now=NOW):
    source, target, safety, readers = case
    return DatabaseMigrationPreflight(*readers, clock=lambda: now, max_age_seconds=60).inspect(
        source,
        target,
        safety,
        source_revision="a" * 64,
    )


def test_success_verifies_only_metadata_gates_and_never_executes(case):
    result = inspect(case)
    assert result["preflight"]["status"] == "passed"
    gates = {gate["name"]: gate["status"] for gate in result["required_gates"]}
    assert {name for name, state in gates.items() if state == "verified"} == {
        "source_target_ownership",
        "source_inventory",
        "supported_schema_and_extensions",
    }
    assert gates["all_writers_controlled"] == gates["recovery_rehearsal"] == "unverified"
    assert result["approval_required"] and not result["ready_to_cutover"]
    assert result["execution_status"] == "blocked"
    assert json.loads(json.dumps(result))["plan_id"] == result["plan_id"]


@pytest.mark.parametrize("which", [0, 1])
def test_collector_error_remains_unverified_and_is_not_disclosed(case, which):
    case[3][which].inspect.side_effect = DatabaseInventoryUnavailable("password=DO-NOT-RETURN")
    result = inspect(case)
    assert result["preflight"]["status"] == "blocked"
    assert any(
        c["status"] == "unverified" and c["reason"] == "unavailable" for c in result["preflight"]["checks"]
    )
    assert "DO-NOT-RETURN" not in json.dumps(result)
    assert all(gate["status"] == "unverified" for gate in result["required_gates"])


@pytest.mark.parametrize("field", ["plan_id", "placement"])
def test_foreign_plan_or_placement_cannot_supply_inventory(case, field):
    reader = case[3][0]
    change = "DBM-" + "f" * 64 if field == "plan_id" else case[1]
    kwargs = {field: change}
    if field == "placement":
        kwargs["resource"] = replace(reader.inspect.return_value.resource, placement=change)
    reader.inspect.return_value = replace(reader.inspect.return_value, **kwargs)
    result = inspect(case)
    assert "preflight_source_inventory_binding_mismatch" in result["blockers"]


@pytest.mark.parametrize("resource_only", [False, True])
@pytest.mark.parametrize("delta", [-61, 1])
def test_stale_and_future_evidence_cannot_verify_gates(case, resource_only, delta):
    reader = case[3][0]
    old = reader.inspect.return_value
    at = NOW + timedelta(seconds=delta)
    reader.inspect.return_value = replace(
        old, **({"resource": replace(old.resource, observed_at=at)} if resource_only else {"observed_at": at})
    )
    assert "preflight_source_inventory_stale_or_future" in inspect(case)["blockers"]


def test_freshness_is_checked_after_both_readers_finish(case):
    result = inspect(case, now=NOW + timedelta(seconds=61))
    assert result["preflight"]["inventories"] == {}
    assert all(gate["status"] == "unverified" for gate in result["required_gates"])


def test_evidence_identity_changes_on_observed_drift_without_reusing_plan_approval(case):
    original = inspect(case)
    assert original["preflight"]["expires_at"] == (NOW + timedelta(seconds=60)).isoformat()
    assert original["preflight"]["evidence_id"] == inspect(case)["preflight"]["evidence_id"]
    case[3][0].inspect.return_value = replace(case[3][0].inspect.return_value, server_version_num=170006)
    changed = inspect(case)
    assert changed["plan_id"] == original["plan_id"]
    assert changed["preflight"]["evidence_id"] != original["preflight"]["evidence_id"]


def test_report_does_not_extend_old_resource_proof_expiration(case):
    old = case[3][0].inspect.return_value
    case[3][0].inspect.return_value = replace(
        old, resource=replace(old.resource, observed_at=NOW - timedelta(seconds=50))
    )
    assert inspect(case)["preflight"]["expires_at"] == (NOW + timedelta(seconds=10)).isoformat()


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({"server_version_num": 160008}, "declared_versions"),
        ({"collation": "en_US.UTF-8"}, "database_locale"),
        ({"extensions": (("plpgsql", "1.0"), ("vector", "0.8.0"))}, "schema_and_extensions"),
        ({"table_count": 1}, "schema_and_extensions"),
        ({"schema_status": "unsupported", "schema_sha256": None}, "schema_and_extensions"),
    ],
)
def test_incompatible_target_metadata_is_blocked(case, change, expected):
    reader = case[3][1]
    reader.inspect.return_value = replace(reader.inspect.return_value, **change)
    result = inspect(case)
    assert "preflight_" + expected + "_incompatible" in result["blockers"]
    assert result["execution_status"] == "blocked"


def test_empty_source_is_not_a_supported_copy_source(case):
    case[3][0].inspect.return_value = replace(case[3][0].inspect.return_value, table_count=0)
    assert "preflight_schema_and_extensions_incompatible" in inspect(case)["blockers"]


def test_preflight_does_not_remove_route_or_policy_blockers(case):
    source, target, safety, readers = case
    target = replace(target, location=DatabaseLocation("onprem", "vm_postgresql", "registered-vm", "dc-a"))
    safety = replace(safety, method="cdc")
    identity = plan_database_migration(source, target, safety, source_revision="a" * 64)["plan_id"]
    readers[0].inspect.return_value = replace(readers[0].inspect.return_value, plan_id=identity)
    readers[1].inspect.return_value = replace(
        readers[1].inspect.return_value,
        plan_id=identity,
        placement=target,
        resource=replace(readers[1].inspect.return_value.resource, placement=target),
    )
    result = inspect((source, target, safety, readers))
    assert result["preflight"]["status"] == "passed"
    assert result["blockers"] == ["route_not_implemented", "continuous_sync_not_implemented"]
    assert not result["ready_to_cutover"]


@pytest.mark.parametrize("age", [True, 0, 301, 1.5])
def test_freshness_configuration_is_explicit_and_bounded(case, age):
    with pytest.raises(ValueError):
        DatabaseMigrationPreflight(*case[3], clock=lambda: NOW, max_age_seconds=age)
