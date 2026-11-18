"""Bind reviewed preservation evidence to one durable environment operation.

This module is policy only. It does not expose an HTTP route, dispatch a worker
or turn a preservation review into authority by itself. The PostgreSQL adapter
must lock the current review and gate records and consume them atomically with
operation/outbox admission.
"""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime

from application.environment_gate_review import (
    RegisteredPreservationGatePolicy,
    assess_preservation_gate,
    preservation_gate_observations,
    validate_preservation_gate_record,
)
from application.environment_jobs import RegisteredEnvironmentJob
from domain.environment_transition import _ref, _time


@dataclass(frozen=True)
class RegisteredEnvironmentExecution:
    """Server-owned composition of a fixed runtime and preservation policy."""

    job: RegisteredEnvironmentJob
    policy: RegisteredPreservationGatePolicy
    review_registration_id: str

    def __post_init__(self):
        if not isinstance(self.job, RegisteredEnvironmentJob) or not isinstance(
            self.policy, RegisteredPreservationGatePolicy
        ):
            raise TypeError("Typed environment job and preservation policy required")
        _ref(self.review_registration_id)
        scope = self.policy.scope
        transfer = self.job.transfer
        if (
            scope.organization_id != self.job.owner.organization_id
            or scope.organization_id != transfer.source.organization_id
            or scope.application_id != transfer.source.application_id
            or scope.source_revision != transfer.source_revision
            or self.review_registration_id != transfer.registration_ref
        ):
            raise ValueError("Environment execution scope differs from registered transfer")

    @property
    def revision(self):
        value = {
            "schema_version": 1,
            "profile": "registered_environment_execution_v1",
            "job_revision": self.job.revision,
            "policy": self.policy.document(),
            "review_registration_id": self.review_registration_id,
        }
        return hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()


def require_current_execution_gate(execution, document, *, now: datetime, expected_record_id: str):
    """Require an exact G7 record and re-evaluate its evidence at ``now``."""
    if not isinstance(execution, RegisteredEnvironmentExecution):
        raise TypeError("Registered environment execution required")
    _time(now)
    document = validate_preservation_gate_record(execution.policy, document)
    if document["record_id"] != expected_record_id or document["gate"] != "G7":
        raise ValueError("Exact pre-effect environment gate required")
    current = assess_preservation_gate(
        execution.policy,
        "G7",
        preservation_gate_observations(document),
        now=now,
    )
    if current["gate_status"] != "passed":
        raise ValueError("Environment execution evidence expired or is incomplete")
    return document


def environment_execution_command(
    principal,
    execution,
    *,
    review_id,
    report_id,
    gate_record_id,
    request_key,
    confirm_write_pause,
    confirm_websocket_reconnect,
):
    """Create a bounded credential-free command for the registered worker."""
    from domain.access import Principal

    if not isinstance(principal, Principal) or not isinstance(execution, RegisteredEnvironmentExecution):
        raise PermissionError("Registered environment execution principal required")
    for value in (review_id, report_id, gate_record_id, request_key):
        if not isinstance(value, str) or not value:
            raise ValueError("Exact environment approval references required")
    if confirm_write_pause is not True or confirm_websocket_reconnect is not True:
        raise ValueError("Explicit write pause and WebSocket reconnect consent required")
    return {
        "schema_version": 1,
        "profile": "registered_environment_execution_v1",
        "registration_id": execution.job.id,
        "registration_revision": execution.revision,
        "review_registration_id": execution.review_registration_id,
        "review_id": review_id,
        "report_id": report_id,
        "gate_policy_id": execution.policy.document()["policy_id"],
        "gate_record_id": gate_record_id,
        "organization_id": principal.organization_id,
        "created_by": principal.user_id,
        "request_key": request_key,
        "action": "transfer",
        "write_pause_consent": True,
        "websocket_reconnect_consent": True,
    }
