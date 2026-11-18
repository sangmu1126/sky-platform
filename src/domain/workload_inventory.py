"""Registered workload dependency inventory without execution authority.

The inventory covers every dependency category even when the verified result is
absence. A missing category is never interpreted as statelessness. Locations
are opaque registered references, never DSNs, URLs, credentials or commands.
"""

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime

from domain.environment_transition import TransitionScope, _ref, _time

DEPENDENCY_CATEGORIES = (
    "cache",
    "database",
    "external_api",
    "filesystem",
    "object_store",
    "queue",
    "session_state",
)
COMPONENT_ROLES = (
    "http_service",
    "realtime_gateway",
    "scheduled_job",
    "worker",
)
ACCESS_MODES = ("read", "read_write", "write")
CONTINUITY_STRATEGIES = ("drain_reconnect", "migrate", "rebind", "retain")
COVERAGE_STATUSES = ("present", "unknown", "verified_absent")


def _canonical_refs(values, label, *, maximum=64):
    if (
        not isinstance(values, tuple)
        or not 1 <= len(values) <= maximum
        or tuple(sorted(values)) != values
        or len(set(values)) != len(values)
    ):
        raise ValueError(f"Canonical nonempty {label} required")
    for value in values:
        _ref(value)


@dataclass(frozen=True)
class RegisteredDependencyPolicy:
    logical_ref: str
    category: str
    component_refs: tuple[str, ...]
    access_mode: str
    source_location_ref: str
    target_location_ref: str
    strategy: str

    def __post_init__(self):
        for value in (self.logical_ref, self.source_location_ref, self.target_location_ref):
            _ref(value)
        _canonical_refs(self.component_refs, "dependency component references")
        if self.category not in DEPENDENCY_CATEGORIES or self.access_mode not in ACCESS_MODES:
            raise ValueError("Registered dependency category and access mode required")
        if self.strategy not in CONTINUITY_STRATEGIES:
            raise ValueError("Registered dependency continuity strategy required")
        if self.strategy == "drain_reconnect" and self.category != "session_state":
            raise ValueError("Drain and reconnect is only a session-state strategy")
        if self.strategy == "retain" and self.source_location_ref != self.target_location_ref:
            raise ValueError("Retained dependency location cannot change")
        if self.strategy in {"migrate", "rebind"} and self.source_location_ref == self.target_location_ref:
            raise ValueError("Migrated or rebound dependency requires a distinct target location")


@dataclass(frozen=True)
class RegisteredWorkloadInventory:
    inventory_ref: str
    scope: TransitionScope
    component_roles: tuple[tuple[str, str], ...]
    dependency_policies: tuple[RegisteredDependencyPolicy, ...]
    max_age_seconds: int = 300

    def __post_init__(self):
        _ref(self.inventory_ref)
        if not isinstance(self.scope, TransitionScope):
            raise TypeError("Typed workload transition scope required")
        if (
            not isinstance(self.component_roles, tuple)
            or not 1 <= len(self.component_roles) <= 64
            or tuple(sorted(self.component_roles)) != self.component_roles
            or len({value[0] for value in self.component_roles}) != len(self.component_roles)
        ):
            raise ValueError("Canonical registered workload components required")
        for component_ref, role in self.component_roles:
            _ref(component_ref)
            if role not in COMPONENT_ROLES:
                raise ValueError("Registered workload component role required")
        if (
            not isinstance(self.dependency_policies, tuple)
            or len(self.dependency_policies) > 128
            or not all(isinstance(value, RegisteredDependencyPolicy) for value in self.dependency_policies)
            or tuple(sorted(self.dependency_policies, key=lambda value: value.logical_ref))
            != self.dependency_policies
            or len({value.logical_ref for value in self.dependency_policies}) != len(self.dependency_policies)
        ):
            raise ValueError("Canonical registered dependency policies required")
        components = {value[0] for value in self.component_roles}
        if any(not set(value.component_refs) <= components for value in self.dependency_policies):
            raise ValueError("Dependency policy references an unregistered workload component")
        if type(self.max_age_seconds) is not int or not 1 <= self.max_age_seconds <= 300:
            raise ValueError("Bounded workload inventory freshness required")

    def document(self):
        value = {
            "schema_version": 1,
            "profile": "registered_workload_dependency_inventory_v1",
            "inventory_ref": self.inventory_ref,
            "scope": asdict(self.scope),
            "component_roles": [list(value) for value in self.component_roles],
            "dependency_policies": [asdict(value) for value in self.dependency_policies],
            "categories": list(DEPENDENCY_CATEGORIES),
            "max_age_seconds": self.max_age_seconds,
        }
        digest = hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        return {**value, "inventory_id": "WIR-" + digest}


@dataclass(frozen=True)
class ObservedWorkloadDependency:
    logical_ref: str
    category: str
    component_refs: tuple[str, ...]
    access_mode: str
    location_ref: str

    def __post_init__(self):
        for value in (self.logical_ref, self.location_ref):
            _ref(value)
        _canonical_refs(self.component_refs, "observed dependency component references")
        if self.category not in DEPENDENCY_CATEGORIES or self.access_mode not in ACCESS_MODES:
            raise ValueError("Observed dependency category and access mode required")


@dataclass(frozen=True)
class WorkloadInventorySnapshot:
    inventory_id: str
    scope: TransitionScope
    endpoint: str
    component_roles: tuple[tuple[str, str], ...]
    coverage: tuple[tuple[str, str], ...]
    dependencies: tuple[ObservedWorkloadDependency, ...]
    evidence_refs: tuple[str, ...]
    observed_at: datetime
    expires_at: datetime

    def __post_init__(self):
        if not isinstance(self.inventory_id, str) or not self.inventory_id.startswith("WIR-"):
            raise ValueError("Exact workload inventory registration required")
        if not isinstance(self.scope, TransitionScope) or self.endpoint not in {"source", "target"}:
            raise ValueError("Typed workload inventory endpoint required")
        if (
            not isinstance(self.component_roles, tuple)
            or tuple(sorted(self.component_roles)) != self.component_roles
            or len({value[0] for value in self.component_roles}) != len(self.component_roles)
        ):
            raise ValueError("Canonical observed workload components required")
        for component_ref, role in self.component_roles:
            _ref(component_ref)
            if role not in COMPONENT_ROLES:
                raise ValueError("Observed workload component role required")
        if (
            not isinstance(self.coverage, tuple)
            or tuple(value[0] for value in self.coverage) != DEPENDENCY_CATEGORIES
            or any(value[1] not in COVERAGE_STATUSES for value in self.coverage)
        ):
            raise ValueError("Every dependency category needs explicit coverage")
        if (
            not isinstance(self.dependencies, tuple)
            or len(self.dependencies) > 128
            or not all(isinstance(value, ObservedWorkloadDependency) for value in self.dependencies)
            or tuple(sorted(self.dependencies, key=lambda value: value.logical_ref)) != self.dependencies
            or len({value.logical_ref for value in self.dependencies}) != len(self.dependencies)
        ):
            raise ValueError("Canonical bounded observed dependencies required")
        status = dict(self.coverage)
        for category in DEPENDENCY_CATEGORIES:
            count = sum(value.category == category for value in self.dependencies)
            if (status[category] == "present") != (count > 0):
                raise ValueError("Dependency coverage differs from observed dependencies")
        _canonical_refs(self.evidence_refs, "workload inventory evidence references")
        _time(self.observed_at)
        _time(self.expires_at)
        if self.expires_at <= self.observed_at:
            raise ValueError("Positive workload inventory evidence lifetime required")
