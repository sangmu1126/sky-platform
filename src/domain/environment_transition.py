"""Internal contracts for preserving workload capabilities across environments.

These values are trusted collector/registry port results, not client JSON or
authenticated receipts. Hashes identify content; they do not prove provenance.
An agent proposal cannot substitute for a measured or inspected result.
"""

import re
from dataclasses import dataclass
from datetime import datetime


def _ref(value: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", value):
        raise ValueError("Registered transition reference required")


def _digest(value: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise ValueError("Transition revision digest required")


def _time(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Timezone-aware transition timestamp required")


# Each criterion must describe an outcome, not demand the same vendor product.
# For a stateless app, the data criterion can verify absence of durable state;
# omission is never equivalent to a verified absence of a requirement.
BASELINE_CAPABILITIES = (
    "application_runtime",
    "persistent_data",
    "identity_access",
    "transport_security",
    "secret_management",
    "audit_logging",
    "monitoring",
    "backup_restore",
    "traffic_cutover",
    "recovery",
    "data_residency",
    "process_session_state",
)


@dataclass(frozen=True)
class TransitionScope:
    organization_id: str
    application_id: str
    source_environment_ref: str
    target_environment_ref: str
    source_revision: str
    source_configuration_revision: str
    target_configuration_revision: str

    def __post_init__(self) -> None:
        for value in (
            self.organization_id,
            self.application_id,
            self.source_environment_ref,
            self.target_environment_ref,
        ):
            _ref(value)
        if self.source_environment_ref == self.target_environment_ref:
            raise ValueError("Distinct registered environments required")
        for value in (
            self.source_revision,
            self.source_configuration_revision,
            self.target_configuration_revision,
        ):
            _digest(value)


@dataclass(frozen=True)
class PreservationRequirement:
    capability: str
    criterion_ref: str
    criterion_revision: str

    def __post_init__(self) -> None:
        _ref(self.capability)
        _ref(self.criterion_ref)
        _digest(self.criterion_revision)


def validate_preservation_requirements(requirements: tuple[PreservationRequirement, ...]) -> None:
    if (
        not isinstance(requirements, tuple)
        or not 1 <= len(requirements) <= 64
        or not all(isinstance(item, PreservationRequirement) for item in requirements)
    ):
        raise ValueError("Bounded immutable preservation requirements required")
    names = [item.capability for item in requirements]
    if len(set(names)) != len(names):
        raise ValueError("Duplicate preservation capability")
    if not set(BASELINE_CAPABILITIES) <= set(names):
        raise ValueError("Baseline preservation criteria cannot be omitted")


@dataclass(frozen=True)
class PreservationObservation:
    scope: TransitionScope
    requirement: PreservationRequirement
    endpoint: str
    evidence_ref: str
    verifier_ref: str
    observed_at: datetime
    expires_at: datetime
    status: str
    origin: str = "collector"

    def __post_init__(self) -> None:
        if not isinstance(self.scope, TransitionScope) or not isinstance(
            self.requirement, PreservationRequirement
        ):
            raise TypeError("Typed transition scope and criterion required")
        if self.endpoint not in {"source", "target"}:
            raise ValueError("Invalid transition endpoint")
        for value in (self.evidence_ref, self.verifier_ref):
            _ref(value)
        _time(self.observed_at)
        _time(self.expires_at)
        if self.expires_at <= self.observed_at:
            raise ValueError("Positive evidence lifetime required")
        if self.status not in {"verified", "failed", "unknown"}:
            raise ValueError("Invalid preservation observation status")
        if self.origin not in {"collector", "agent_proposal"}:
            raise ValueError("Invalid preservation observation origin")
