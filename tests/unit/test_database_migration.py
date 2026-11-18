"""Migration review cannot widen the existing executor's authority."""

import json
from dataclasses import FrozenInstanceError, replace

import pytest

from domain.database_migration import DatabaseLocation, DatabasePlacement, MigrationSafetyPolicy
from engine.database_migration import plan_database_migration


def placements():
    source = DatabasePlacement(
        "org",
        "app",
        "shared_workload",
        DatabaseLocation("aws", "rds_postgresql", "111111111111", "ap-northeast-2"),
        "pool",
        "app_db",
        "source-owner",
        16,
    )
    return source, replace(
        source, role="dedicated_workload", instance_id="dedicated", owner_ref="target-owner"
    )


def policy():
    return MigrationSafetyPolicy(120, 600, 86400)


def plan(source, target, safety=None):
    return plan_database_migration(source, target, safety or policy(), source_revision="a" * 64)


def test_existing_executor_is_not_execution_authority_or_proof_of_safety():
    result = plan(*placements())
    assert result["route_status"] == "existing_executor"
    assert result["blockers"] == []
    assert result["execution_status"] == "blocked"
    assert result["approval_required"] is True
    assert result["ready_to_cutover"] is False
    assert all(gate["status"] == "unverified" for gate in result["required_gates"])
    assert {g["name"] for g in result["required_gates"]} >= {
        "all_writers_controlled",
        "final_sync_integrity",
        "recovery_rehearsal",
        "target_security_equivalence",
        "write_pause_budget_measured",
    }
    assert "continuous_sync_caught_up" not in {g["name"] for g in result["required_gates"]}
    assert json.loads(json.dumps(result)) == result


@pytest.mark.parametrize(
    "location",
    [
        DatabaseLocation("onprem", "vm_postgresql", "registered-vm-1", "datacenter-a"),
        DatabaseLocation("gcp", "cloud_sql_postgresql", "registered-project", "asia-northeast3"),
        DatabaseLocation("aws", "rds_postgresql", "222222222222", "ap-northeast-2"),
        DatabaseLocation("aws", "rds_postgresql", "111111111111", "ap-northeast-1"),
    ],
)
def test_cross_environment_plan_is_describable_but_not_executable(location):
    source, target = placements()
    result = plan(source, replace(target, location=location))
    assert result["target"]["location"] == {
        "provider": location.provider,
        "backend": location.backend,
        "authority_ref": location.authority_ref,
        "location": location.location,
    }
    assert result["route_status"] == "unsupported_by_sky"
    assert "route_not_implemented" in result["blockers"]
    assert result["ready_to_cutover"] is False


def test_placement_does_not_require_shared_to_dedicated_but_executor_still_does():
    source, target = placements()
    result = plan(replace(source, role="existing_workload"), target)
    assert result["route_status"] == "unsupported_by_sky"
    assert result["execution_status"] == "blocked"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("organization_id", "another-org", "ownership"),
        ("application_id", "another-app", "ownership"),
        ("role", "sky_state", "Control-plane"),
    ],
)
def test_ownership_and_control_plane_boundaries_are_not_relaxed(field, value, message):
    source, target = placements()
    with pytest.raises(ValueError, match=message):
        plan(source, replace(target, **{field: value}))
    if field == "role":
        with pytest.raises(ValueError, match=message):
            plan(replace(source, role=value), target)


@pytest.mark.parametrize(
    ("safety", "blocker"),
    [
        (MigrationSafetyPolicy(0, 600, 86400), "write_freeze_requires_pause_budget"),
        (MigrationSafetyPolicy(120, 600, 86400, method="cdc"), "continuous_sync_not_implemented"),
        (
            MigrationSafetyPolicy(120, 600, 86400, recovery_point_objective_seconds=5),
            "lossy_recovery_policy_not_supported",
        ),
    ],
)
def test_unsupported_operating_contract_is_explicitly_blocked(safety, blocker):
    result = plan(*placements(), safety)
    assert blocker in result["blockers"]
    assert result["execution_status"] == "blocked"


def test_version_change_and_same_instance_move_are_not_silently_allowed():
    source, target = placements()
    assert (
        "postgres_major_change_not_supported" in plan(source, replace(target, postgres_major=17))["blockers"]
    )
    with pytest.raises(ValueError, match="different database instance"):
        plan(source, replace(target, instance_id=source.instance_id, database_name="another_db"))


def test_identity_binds_destination_source_revision_and_safety_policy():
    source, target = placements()
    original = plan(source, target)
    variants = [
        original,
        plan(source, replace(target, owner_ref="different-owner")),
        plan(source, replace(target, database_name="different_db")),
        plan(source, replace(target, postgres_major=17)),
        plan(source, target, replace(policy(), write_pause_budget_seconds=60)),
        plan(source, target, replace(policy(), recovery_time_objective_seconds=300)),
        plan(source, target, replace(policy(), source_retention_seconds=172800)),
        plan_database_migration(source, target, policy(), source_revision="b" * 64),
    ]
    assert len({p["plan_id"] for p in variants}) == len(variants)
    assert original == plan(source, target)
    original["source"]["database_name"] = "mutated"
    assert source.database_name == "app_db"
    with pytest.raises(FrozenInstanceError):
        source.instance_id = "mutated"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("write_pause_budget_seconds", True),
        ("write_pause_budget_seconds", -1),
        ("recovery_time_objective_seconds", 0),
        ("source_retention_seconds", 599),
        ("recovery_point_objective_seconds", 0.1),
        ("method", "automatic"),
    ],
)
def test_malformed_or_inconsistent_policy_is_rejected(field, value):
    with pytest.raises(ValueError):
        replace(policy(), **{field: value})


@pytest.mark.parametrize(
    ("provider", "backend", "authority", "location"),
    [
        ("aws", "vm_postgresql", "111111111111", "ap-northeast-2"),
        ("aws", "rds_postgresql", "not-an-account", "ap-northeast-2"),
        ("onprem", "vm_postgresql", "ssh://root@server", "dc-a"),
        ("gcp", "cloud_sql_postgresql", "project", "https://server"),
    ],
)
def test_location_accepts_registered_references_not_connection_strings(
    provider, backend, authority, location
):
    with pytest.raises(ValueError):
        DatabaseLocation(provider, backend, authority, location)


@pytest.mark.parametrize("revision", ["", "a" * 63, "A" * 64, None])
def test_plan_requires_exact_source_revision(revision):
    with pytest.raises(ValueError, match="revision"):
        plan_database_migration(*placements(), policy(), source_revision=revision)
