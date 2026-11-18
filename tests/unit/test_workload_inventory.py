"""All workload dependency categories require registered exhaustive evidence."""

from copy import deepcopy
from dataclasses import replace
from datetime import timedelta

import pytest

from domain.environment_transition import TransitionScope
from domain.workload_inventory import (
    DEPENDENCY_CATEGORIES,
    ObservedWorkloadDependency,
    RegisteredDependencyPolicy,
    RegisteredWorkloadInventory,
    WorkloadInventorySnapshot,
)
from engine.workload_inventory import (
    assess_workload_inventory,
    validate_workload_inventory_report,
)
from tests.unit.test_environment_transition import NOW


def registration():
    scope = TransitionScope("org", "app", "aws-prod", "vm-target", "a" * 64, "b" * 64, "c" * 64)
    policies = (
        RegisteredDependencyPolicy(
            "live-session",
            "session_state",
            ("api",),
            "read_write",
            "aws-memory",
            "vm-memory",
            "drain_reconnect",
        ),
        RegisteredDependencyPolicy(
            "partner-api",
            "external_api",
            ("api",),
            "read",
            "partner-service",
            "partner-service",
            "retain",
        ),
        RegisteredDependencyPolicy(
            "primary-db",
            "database",
            ("api", "jobs"),
            "read_write",
            "aws-database",
            "vm-database",
            "migrate",
        ),
        RegisteredDependencyPolicy(
            "uploads",
            "object_store",
            ("api", "jobs"),
            "read_write",
            "aws-objects",
            "vm-objects",
            "rebind",
        ),
    )
    return RegisteredWorkloadInventory(
        "app-dependencies-v1",
        scope,
        (("api", "http_service"), ("jobs", "worker")),
        tuple(sorted(policies, key=lambda value: value.logical_ref)),
    )


def snapshot(value, endpoint, **changes):
    dependencies = tuple(
        ObservedWorkloadDependency(
            policy.logical_ref,
            policy.category,
            policy.component_refs,
            policy.access_mode,
            policy.source_location_ref if endpoint == "source" else policy.target_location_ref,
        )
        for policy in value.dependency_policies
    )
    present = {item.category for item in dependencies}
    base = WorkloadInventorySnapshot(
        value.document()["inventory_id"],
        value.scope,
        endpoint,
        value.component_roles,
        tuple(
            (category, "present" if category in present else "verified_absent")
            for category in DEPENDENCY_CATEGORIES
        ),
        dependencies,
        (endpoint + "-dependency-scan",),
        NOW - timedelta(seconds=10),
        NOW + timedelta(seconds=60),
    )
    return replace(base, **changes)


def report(value=None, source=None, target=None, now=NOW):
    value = value or registration()
    return assess_workload_inventory(
        value,
        source or snapshot(value, "source"),
        target or snapshot(value, "target"),
        now=now,
    )


def test_complete_registered_inventory_verifies_writers_workers_and_absence():
    value = registration()
    result = report(value)
    assert result["status"] == "verified" and not result["execution_authorized"]
    assert result["endpoint_status"] == {"source": "verified", "target": "verified"}
    source = result["source"]
    assert [item[0] for item in source["component_roles"]] == ["api", "jobs"]
    assert dict(source["coverage"])["filesystem"] == "verified_absent"
    assert dict(source["coverage"])["queue"] == "verified_absent"
    assert {item["logical_ref"] for item in source["dependencies"]} == {
        "live-session",
        "partner-api",
        "primary-db",
        "uploads",
    }
    assert validate_workload_inventory_report(value, result) == result


@pytest.mark.parametrize("change", ["unknown_absence", "component", "binding", "stale"])
def test_missing_or_drifted_inventory_never_becomes_verified_absence(change):
    value = registration()
    source = snapshot(value, "source")
    if change == "unknown_absence":
        source = replace(
            source,
            coverage=tuple(
                (category, "unknown" if category == "filesystem" else status)
                for category, status in source.coverage
            ),
        )
    elif change == "component":
        source = replace(source, component_roles=(("api", "http_service"),))
    elif change == "binding":
        dependencies = list(source.dependencies)
        dependencies[0] = replace(dependencies[0], location_ref="unregistered-location")
        source = replace(source, dependencies=tuple(dependencies))
    else:
        source = replace(
            source, observed_at=NOW - timedelta(seconds=301), expires_at=NOW + timedelta(seconds=1)
        )
    result = report(value, source=source)
    assert result["status"] == "blocked" and result["endpoint_status"]["source"] == "unknown"


def test_unregistered_dependency_and_policy_shortcuts_are_rejected():
    value = registration()
    source = snapshot(value, "source")
    extra = ObservedWorkloadDependency("hidden-writer", "filesystem", ("jobs",), "write", "local-disk")
    changed = replace(
        source,
        dependencies=tuple(sorted((*source.dependencies, extra), key=lambda item: item.logical_ref)),
        coverage=tuple(
            (category, "present" if category == "filesystem" else status)
            for category, status in source.coverage
        ),
    )
    result = report(value, source=changed)
    assert result["status"] == "blocked"
    with pytest.raises(ValueError, match="Drain and reconnect"):
        replace(value.dependency_policies[0], category="database")
    with pytest.raises(ValueError, match="Retained dependency"):
        replace(value.dependency_policies[1], target_location_ref="other-service")


def test_report_identity_binds_full_inventory_and_tampering_is_rejected():
    value = registration()
    original = report(value)
    changed = report(
        value,
        source=replace(snapshot(value, "source"), evidence_refs=("different-source-scan",)),
    )
    assert original["report_id"] != changed["report_id"]
    tampered = deepcopy(original)
    tampered["source"]["dependencies"][0]["access_mode"] = "read"
    with pytest.raises(ValueError, match="Invalid workload"):
        validate_workload_inventory_report(value, tampered)
