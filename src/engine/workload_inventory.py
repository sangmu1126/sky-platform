"""Assess registered source/target dependency inventories without effects."""

import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timedelta

from domain.environment_transition import _time
from domain.workload_inventory import (
    DEPENDENCY_CATEGORIES,
    ObservedWorkloadDependency,
    RegisteredWorkloadInventory,
    WorkloadInventorySnapshot,
)


def _snapshot_document(snapshot):
    value = asdict(snapshot)
    value["observed_at"] = snapshot.observed_at.isoformat()
    value["expires_at"] = snapshot.expires_at.isoformat()
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False))


def assess_workload_inventory(registration, source, target, *, now: datetime):
    if not isinstance(registration, RegisteredWorkloadInventory):
        raise TypeError("Registered workload inventory required")
    _time(now)
    snapshots = {"source": source, "target": target}
    checks = []
    expected_components = registration.component_roles
    expected = {value.logical_ref: value for value in registration.dependency_policies}
    endpoint_status = {}
    for endpoint, snapshot in snapshots.items():
        blockers = []
        if (
            not isinstance(snapshot, WorkloadInventorySnapshot)
            or snapshot.inventory_id != registration.document()["inventory_id"]
            or snapshot.scope != registration.scope
            or snapshot.endpoint != endpoint
        ):
            raise ValueError("Workload inventory snapshot differs from registration")
        if snapshot.component_roles != expected_components:
            blockers.append("component_inventory_changed")
        if not 0 <= (now - snapshot.observed_at).total_seconds() <= registration.max_age_seconds:
            blockers.append("stale_or_future_inventory")
        if now >= min(
            snapshot.expires_at,
            snapshot.observed_at + timedelta(seconds=registration.max_age_seconds),
        ):
            blockers.append("expired_inventory")
        observed = {value.logical_ref: value for value in snapshot.dependencies}
        if set(observed) != set(expected):
            blockers.append("dependency_set_changed")
        for logical_ref in sorted(set(observed) & set(expected)):
            actual, policy = observed[logical_ref], expected[logical_ref]
            location = policy.source_location_ref if endpoint == "source" else policy.target_location_ref
            if (
                actual.category != policy.category
                or actual.component_refs != policy.component_refs
                or actual.access_mode != policy.access_mode
                or actual.location_ref != location
            ):
                blockers.append("dependency_binding_changed:" + logical_ref)
        coverage = dict(snapshot.coverage)
        for category in DEPENDENCY_CATEGORIES:
            required = any(value.category == category for value in expected.values())
            wanted = "present" if required else "verified_absent"
            if coverage[category] != wanted:
                blockers.append("category_not_exhaustive:" + category)
        blockers = sorted(set(blockers))
        endpoint_status[endpoint] = "verified" if not blockers else "unknown"
        checks.append({"endpoint": endpoint, "status": endpoint_status[endpoint], "blockers": blockers})

    report = {
        "schema_version": 1,
        "profile": "registered_workload_dependency_inventory_v1",
        "inventory_id": registration.document()["inventory_id"],
        "scope": asdict(registration.scope),
        "evaluated_at": now.isoformat(),
        "expires_at": min(source.expires_at, target.expires_at).isoformat(),
        "status": "verified" if set(endpoint_status.values()) == {"verified"} else "blocked",
        "endpoint_status": endpoint_status,
        "checks": checks,
        "source": _snapshot_document(source),
        "target": _snapshot_document(target),
        "execution_authorized": False,
    }
    digest = hashlib.sha256(
        json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    return {**report, "report_id": "WDI-" + digest}


def validate_workload_inventory_report(registration, document):
    """Recompute internal report content; this does not authenticate its origin."""
    from domain.environment_transition import TransitionScope

    try:
        raw = json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(raw.encode()) > 512 * 1024:
            raise ValueError("Bounded workload inventory report required")

        def snapshot(value):
            return WorkloadInventorySnapshot(
                inventory_id=value["inventory_id"],
                scope=TransitionScope(**value["scope"]),
                endpoint=value["endpoint"],
                component_roles=tuple(tuple(item) for item in value["component_roles"]),
                coverage=tuple(tuple(item) for item in value["coverage"]),
                dependencies=tuple(
                    ObservedWorkloadDependency(**{**item, "component_refs": tuple(item["component_refs"])})
                    for item in value["dependencies"]
                ),
                evidence_refs=tuple(value["evidence_refs"]),
                observed_at=datetime.fromisoformat(value["observed_at"]),
                expires_at=datetime.fromisoformat(value["expires_at"]),
            )

        expected = assess_workload_inventory(
            registration,
            snapshot(document["source"]),
            snapshot(document["target"]),
            now=datetime.fromisoformat(document["evaluated_at"]),
        )
        if json.dumps(expected, sort_keys=True, separators=(",", ":"), allow_nan=False) != raw:
            raise ValueError("Workload inventory report contents changed")
        return json.loads(raw)
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        raise ValueError("Invalid workload inventory report") from None
