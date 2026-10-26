"""Read-only recovery gate. Observations are not execution grants or request fences."""

import re
from datetime import datetime, timedelta

from application.incident_runtime_inspection import IncidentRuntimeInspection
from application.security_hold import validate_release_request
from ports.remote_builds import digest
from ports.state import RecordConflict

OPERATIONS = {
    "runtime_containment": ("security_runtime_containment", "scale_down_requested"),
    "database_restriction": ("security_database_restriction", "verified"),
    "candidate_credentials": ("security_credential_preparation", "prepared_restricted"),
    "credential_executor": ("security_credential_preparation", None),
    "secret_access": ("security_secret_access_fence", "policy_recorded"),
}
UNSUPPORTED = (
    "execution_exclusion",
    "scheduler_fence",
    "provider_requests_settled",
    "data_integrity",
    "candidate_authentication",
    "old_credential_invalidation",
    "secret_policy_propagation",
    "recovery_candidate_admission",
    "one_time_execution_reservation",
)


class IncidentRecoveryReadiness:
    def __init__(self, records, reviews, inspections, *, clock, revalidate):
        if not isinstance(inspections, dict) or set(inspections) - {"runtime", "sky_execution", *OPERATIONS}:
            raise ValueError("Only fixed recovery inspection services are allowed")
        self.scope = IncidentRuntimeInspection(records, None, clock=clock, revalidate=revalidate)
        self.reviews, self.inspections, self.clock = reviews, inspections, clock

    def check(self, principal, job_id, *, review_id, **options):
        started = self.clock()
        base = {k: options[k] for k in ("incident_id", "expected_boundary", "expected_revision")}
        validate_release_request(
            base["incident_id"],
            "recovery-readiness",
            base["expected_revision"],
            base["expected_boundary"],
            started,
        )
        original = self.scope._scope(
            principal, job_id, base["incident_id"], base["expected_boundary"], started
        )

        def guard():
            current = self.scope._scope(
                principal, job_id, base["incident_id"], base["expected_boundary"], started
            )
            if current != original or current.revision != base["expected_revision"]:
                raise RecordConflict("Deployment changed during recovery readiness inspection")

        def review():
            guard()
            receipt = self.reviews.check(principal, job_id, review_id=review_id, **options)
            if (
                not isinstance(receipt, dict)
                or receipt.get("review_id") != review_id
                or receipt.get("metadata_revision") != original.revision
                or receipt.get("artifact_review_matched") is not True
                or receipt.get("read_only") is not True
                or receipt.get("state_changed") is not False
                or receipt.get("execution_authorized") is not False
                or receipt.get("recovery_authorized") is not False
            ):
                raise ValueError("Current artifact review recheck required")
            guard()
            return receipt

        review()
        checks = {"artifact_review": {"status": "verified", "reason_code": "fresh_combined_evidence"}}
        for name in ("runtime", "sky_execution", *OPERATIONS):
            guard()
            record, phase = None, None
            if name in OPERATIONS:
                field, phase = OPERATIONS[name]
                record = original.record.get(field)
                if record is None:
                    checks[name] = blocked("operation_not_recorded")
                    continue
                if (
                    not isinstance(record, dict)
                    or (record.get("incident_id"), record.get("boundary_id"))
                    != (base["incident_id"], base["expected_boundary"])
                    or not isinstance(record.get("operation_id"), str)
                    or not re.fullmatch(r"[a-f0-9]{32}", record["operation_id"])
                ):
                    checks[name] = blocked("operation_scope_invalid")
                    continue
            inspector = self.inspections.get(name)
            if inspector is None:
                checks[name] = blocked("live_inspector_not_configured")
                continue
            call_options = {**base, **({"expected_operation_id": record["operation_id"]} if record else {})}
            try:
                receipt = inspector.inspect(principal, job_id, **call_options)
                guard()
                validate_observation(receipt, original.revision, started, self.clock(), record)
                if record is not None and receipt.get("persisted_phase") != record.get("phase"):
                    raise ValueError("Observed operation phase differs from snapshot")
                if phase is not None and record.get("phase") != phase:
                    checks[name] = blocked("operation_outcome_unsettled")
                else:
                    checks[name] = condition(name, receipt)
            except (PermissionError, RecordConflict):
                raise
            except Exception:  # noqa: BLE001 -- only fixed codes, never native diagnostics or credentials
                guard()
                checks[name] = blocked("live_inspection_unavailable")
        # None of today's probes proves these broader properties. In particular,
        # STOPPED is not a global executor fence, and NOLOGIN is not data integrity.
        for name in UNSUPPORTED:
            checks[name] = blocked("trusted_evidence_not_implemented")
        final_review = review()
        completed = datetime.fromisoformat(self.clock())
        if not datetime.fromisoformat(started) <= completed <= datetime.fromisoformat(started) + timedelta(
            seconds=300
        ) or completed >= datetime.fromisoformat(final_review["expires_at"]):
            raise ValueError("Fresh unexpired recovery readiness inspection required")
        guard()
        blockers = [name for name, result in checks.items() if result["status"] != "verified"]
        return {
            "incident_id": base["incident_id"],
            "boundary_id": base["expected_boundary"],
            "metadata_revision": original.revision,
            "review_id": review_id,
            "observed_at": completed.isoformat(),
            "checks": checks,
            "blocking_checks": blockers,
            "evidence_digest": digest(
                {"checks": checks, "review": final_review, "revision": original.revision}
            ),
            "ready_for_recovery": not blockers,
            "execution_authorized": False,
            "recovery_authorized": False,
            "hold_released": False,
            "credentials_activated": False,
            "state_changed": False,
            "read_only": True,
        }


def blocked(code):
    return {"status": "blocked", "reason_code": code}


def validate_observation(receipt, revision, started, completed, record):
    if (
        not isinstance(receipt, dict)
        or receipt.get("metadata_revision") != revision
        or receipt.get("read_only") is not True
        or receipt.get("state_changed") is not False
        or ("recovery_authorized" in receipt and receipt["recovery_authorized"] is not False)
        or (record is not None and receipt.get("operation_id") != record["operation_id"])
    ):
        raise ValueError("Incident-bound read-only observation required")
    observed = datetime.fromisoformat(receipt["observed_at"])
    if observed.tzinfo is None or not datetime.fromisoformat(started) <= observed <= datetime.fromisoformat(
        completed
    ):
        raise ValueError("Fresh native observation required")


def condition(name, value):
    verified = {
        "sky_execution": lambda: (
            value.get("fence_scope") == "sky_postgres_operations"
            and value.get("sky_operation_admission_fenced") is True
            and value.get("sky_worker_external_intents_fenced") is True
            and value.get("registered_operation_requests_settled") is True
            and value.get("pending_inventory_complete") is True
            and value.get("pending_operation_ids") == []
        ),
        "runtime": lambda: value.get("registered_service_quiescent") is True,
        "runtime_containment": lambda: value.get("scale_down_configuration_observed") is True,
        "database_restriction": lambda: (
            value.get("observed_state") == "restricted"
            and value.get("login_enabled") is False
            and type(value.get("active_sessions")) is int
            and value["active_sessions"] == 0
        ),
        "candidate_credentials": lambda: (
            value.get("observed_state") == "restricted_candidate_observed"
            and value.get("candidate_state") == "registered_candidate"
            and value.get("login_enabled") is False
            and type(value.get("active_sessions")) is int
            and value["active_sessions"] == 0
        ),
        "credential_executor": lambda: value.get("executor_state") == "stopped",
        "secret_access": lambda: (
            value.get("policy_state") == "runtime_roles_denied" and value.get("candidate_protected") is True
        ),
    }[name]()
    return (
        {"status": "verified", "reason_code": "limited_native_observation"}
        if verified
        else blocked("native_condition_not_met")
    )
