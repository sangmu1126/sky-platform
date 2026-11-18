"""Registered staged preservation review, never production execution admission.

An early gate may pass while explicitly carrying later obligations. Missing or
expired evidence is never a verified absence. The existing all-criteria review
is preserved; callers must not treat this staged result as its approval.
"""

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime
from types import MappingProxyType

from domain.environment_transition import (
    PreservationRequirement,
    TransitionScope,
    _ref,
    _time,
    validate_preservation_requirements,
)
from engine.environment_transition import assess_environment_transition

GATES = tuple("G" + str(index) for index in range(9))
# Latest permitted checks for this first, bounded write-pause profile. A
# registered policy may require an earlier check, but cannot defer these later.
# Data/route postconditions can only be measured after the controlled effect.
# A qualified transfer/recovery rehearsal is a separate prerequisite at G5.
LATEST_GATE = MappingProxyType(
    {
        "application_runtime": "G3",
        "persistent_data": "G8",
        "identity_access": "G6",
        "transport_security": "G6",
        "secret_management": "G6",
        "audit_logging": "G6",
        "monitoring": "G6",
        "backup_restore": "G6",
        "traffic_cutover": "G8",
        "recovery": "G5",
        "data_residency": "G1",
        "process_session_state": "G1",
        "registered_authorization": "G0",
        "dependency_inventory": "G1",
        "source_patch_safety": "G2",
        "artifact_identity": "G3",
        "functional_scenarios": "G4",
        "transfer_rehearsal": "G5",
        "current_execution_approval": "G7",
        "post_cutover_validation": "G8",
    }
)
REQUIRED_CAPABILITIES = frozenset(LATEST_GATE)


def _hash(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def _bind_parent(value, parent):
    payload = {key: item for key, item in value.items() if key != "record_id"}
    payload["previous_record_id"] = parent
    return {**payload, "record_id": "EGR-" + _hash(payload)}


@dataclass(frozen=True)
class RegisteredPreservationGatePolicy:
    """Server registry value. No public payload may construct or weaken it."""

    policy_ref: str
    scope: TransitionScope
    requirements: tuple[PreservationRequirement, ...]
    due_gates: tuple[tuple[str, str], ...]

    def __post_init__(self):
        _ref(self.policy_ref)
        if not isinstance(self.scope, TransitionScope):
            raise TypeError("Typed registered transition scope required")
        validate_preservation_requirements(self.requirements)
        capabilities = {item.capability for item in self.requirements}
        if not REQUIRED_CAPABILITIES <= capabilities:
            raise ValueError("Registration, rehearsal and execution approval obligations required")
        if (
            not isinstance(self.due_gates, tuple)
            or any(
                not isinstance(item, tuple)
                or len(item) != 2
                or not all(isinstance(value, str) for value in item)
                for item in self.due_gates
            )
            or len(self.due_gates) != len(capabilities)
            or {item[0] for item in self.due_gates} != capabilities
            or any(gate not in GATES for _, gate in self.due_gates)
            or any(
                capability in LATEST_GATE and gate > LATEST_GATE[capability]
                for capability, gate in self.due_gates
            )
        ):
            raise ValueError("Every obligation needs a unique gate within its protection floor")

    def document(self):
        value = {
            "policy_ref": self.policy_ref,
            "scope": asdict(self.scope),
            "requirements": [asdict(item) for item in sorted(self.requirements, key=lambda v: v.capability)],
            "due_gates": dict(sorted(self.due_gates)),
            "profile": "registered_write_pause_preservation_v2",
        }
        return {**value, "policy_id": "EGP-" + _hash(value)}


def assess_preservation_gate(policy, gate, observations, *, now):
    if not isinstance(policy, RegisteredPreservationGatePolicy):
        raise TypeError("Registered immutable gate policy required")
    if gate not in GATES:
        raise ValueError("Explicit preservation gate required")
    report = assess_environment_transition(policy.scope, policy.requirements, observations, now=now)
    due = dict(policy.due_gates)
    obligations = []
    for check in report["checks"]:
        capability = check["capability"]
        obligations.append(
            {
                **check,
                "due_gate": due[capability],
                "due_now": due[capability] <= gate,
                "requires_source_verification": check["endpoints"]["source"]["status"] != "verified",
                "requires_target_verification": check["endpoints"]["target"]["status"] != "verified",
            }
        )
    blocked = [item["capability"] for item in obligations if item["due_now"] and item["status"] != "verified"]
    value = {
        "schema_version": 1,
        "policy_id": policy.document()["policy_id"],
        "gate": gate,
        "evaluated_at": report["evaluated_at"],
        "preservation_report": report,
        "obligations": obligations,
        "gate_status": "blocked" if blocked else "passed",
        "blocking_obligations": blocked,
        "carried_obligations": [item["capability"] for item in obligations if item["status"] != "verified"],
        "execution_authorized": False,
        "migration_completed": False,
    }
    return _bind_parent(value, None)


def advance_preservation_gate(policy, previous, gate, observations, *, now):
    """Validate a persisted previous record and prohibit skipping blocked gates.

    The store supplies previous state; it must never come from a request/model.
    Hashes detect content changes, not authenticated origin or execution rights.
    Every new gate recollects/re-evaluates; previous verified status isn't reused.
    """
    if not isinstance(policy, RegisteredPreservationGatePolicy):
        raise TypeError("Registered gate policy required")
    _time(now)
    if previous is None:
        if gate != "G0":
            raise ValueError("Preservation gates must begin at registration")
    else:
        previous = validate_preservation_gate_record(policy, previous)
        index = GATES.index(previous["gate"])
        if gate == previous["gate"]:
            if previous["gate_status"] != "blocked":
                raise ValueError("A passed gate cannot be replayed")
        elif previous["gate_status"] != "passed" or index == 8 or gate != GATES[index + 1]:
            raise ValueError("Cannot skip a blocked or incomplete preservation gate")
        if not isinstance(now, datetime) or now < datetime.fromisoformat(previous["evaluated_at"]):
            raise ValueError("Gate evaluation time cannot move backwards")
    value = assess_preservation_gate(policy, gate, observations, now=now)
    return _bind_parent(value, None if previous is None else previous["record_id"])


def validate_preservation_gate_record(policy, document):
    try:
        raw = json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(raw.encode()) > 512 * 1024:
            raise ValueError("Bounded gate record required")
        observations = preservation_gate_observations(document)
        expected = assess_preservation_gate(
            policy, document["gate"], observations, now=datetime.fromisoformat(document["evaluated_at"])
        )
        parent = document.get("previous_record_id")
        if parent is not None and (
            not isinstance(parent, str)
            or not parent.startswith("EGR-")
            or len(parent) != 68
            or any(value not in "0123456789abcdef" for value in parent[4:])
        ):
            raise ValueError("Exact previous gate reference required")
        expected = _bind_parent(expected, parent)
        if json.dumps(expected, sort_keys=True, separators=(",", ":"), allow_nan=False) != raw:
            raise ValueError("Gate obligations or evidence changed")
        return json.loads(raw)
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        raise ValueError("Invalid persisted preservation gate record") from None


def preservation_gate_observations(document):
    """Rebuild typed observations from a validated-shape gate document.

    This helper does not authenticate a document. Callers must still invoke
    ``validate_preservation_gate_record`` with the server-registered policy.
    It exists so execution admission can re-evaluate evidence at the database
    clock instead of treating the original gate evaluation time as freshness.
    """
    from domain.environment_transition import PreservationObservation

    return tuple(
        PreservationObservation(
            TransitionScope(**item["scope"]),
            PreservationRequirement(**item["requirement"]),
            item["endpoint"],
            item["evidence_ref"],
            item["verifier_ref"],
            datetime.fromisoformat(item["observed_at"]),
            datetime.fromisoformat(item["expires_at"]),
            item["status"],
            item["origin"],
        )
        for item in document["preservation_report"]["observations"]
    )
