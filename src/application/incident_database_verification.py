"""Persist a single authentication probe intent after registered runtime retirement."""

import re
from copy import deepcopy
from uuid import uuid4

from application.incident_runtime_inspection import IncidentRuntimeInspection
from application.incident_secret_access import access_context, access_record_is_valid
from application.security_hold import validate_release_request
from ports.state import RecordConflict

FIELD = "security_database_verification"


class IncidentDatabaseVerification:
    def __init__(self, records, execution, retirement, registration, adapter, *, clock, revalidate):
        self.scope = IncidentRuntimeInspection(records, None, clock=clock, revalidate=revalidate)
        self.writer, self.execution, self.retirement = self.scope.writer, execution, retirement
        self.registration, self.adapter, self.clock = registration, adapter, clock

    def _current(self, principal, job_id, options):
        now = self.clock()
        snapshot = self.scope._scope(
            principal, job_id, options["incident_id"], options["expected_boundary"], now
        )
        if snapshot.revision != options["expected_revision"]:
            raise RecordConflict("Incident changed since database verification review")
        context = access_context(snapshot.record, self.registration)
        policy = snapshot.record.get("security_secret_access_fence")
        if not access_record_is_valid(policy, context) or policy["phase"] != "policy_recorded":
            raise ValueError("Recorded registered runtime Secret denial required")
        if snapshot.record.get("security_runtime_retirement", {}).get("phase") != "retired":
            raise ValueError("Confirmed runtime retirement required before authentication probes")
        control = self.execution.inspect(principal, job_id, **options)
        if (
            control.get("sky_worker_external_intents_fenced") is not True
            or control.get("registered_operation_requests_settled") is not True
            or control.get("pending_inventory_complete") is not True
        ):
            raise ValueError("Fenced settled registered operation paths required")
        retired = self.retirement.inspect(principal, job_id, **options)
        if (
            retired.get("registered_runtime_retirement_verified") is not True
            or retired.get("read_only") is not True
            or retired.get("state_changed") is not False
        ):
            raise ValueError("Fresh registered runtime tombstone verification required")
        return snapshot, context, policy

    def verify(self, principal, job_id, *, expected_fingerprint, **options):
        validate_release_request(
            options["incident_id"],
            "database-verification",
            options["expected_revision"],
            options["expected_boundary"],
            self.clock(),
        )
        if not isinstance(expected_fingerprint, str) or not re.fullmatch(
            r"sha256:[a-f0-9]{64}", expected_fingerprint
        ):
            raise ValueError("Explicit reviewed snapshot fingerprint required")
        snapshot, context, policy = self._current(principal, job_id, options)
        if snapshot.record.get(FIELD) is not None:
            raise ValueError(
                "Existing verification requires inspection; never repeat LOGIN probes automatically"
            )
        intent = {
            "schema_version": 1,
            "operation_id": uuid4().hex,
            "incident_id": options["incident_id"],
            "boundary_id": options["expected_boundary"],
            "requested_by": principal.user_id,
            "requested_at": self.clock(),
            "baseline_fingerprint": expected_fingerprint,
            "candidate_version_id": context["candidate_version_id"],
            "phase": "applying",
        }
        self.writer.patch(
            principal, job_id, snapshot.revision, {FIELD: intent, "promotion_automation_consent": None}
        )
        current_options = {**options, "expected_revision": snapshot.revision + 1}

        def guard():
            current, current_context, current_policy = self._current(principal, job_id, current_options)
            if (
                current.record != {**snapshot.record, FIELD: intent, "promotion_automation_consent": None}
                or current_context != context
                or current_policy != policy
            ):
                raise RecordConflict("Database verification execution ownership changed")
            return current

        try:
            guard()
            result = self.adapter.verify(
                deepcopy(context),
                deepcopy(policy["target"]),
                expected_fingerprint=expected_fingerprint,
                guard=guard,
            )
            required = {
                "baseline_fingerprint",
                "baseline_matched",
                "authentication_verified",
                "previous_password_rejected",
                "login_enabled",
                "active_sessions",
                "credentials_activated",
                "recovery_authorized",
                "candidate_version_id",
                "previous_version_id",
            }
            if (
                not isinstance(result, dict)
                or set(result) != required
                or result["baseline_fingerprint"] != expected_fingerprint
                or result["candidate_version_id"] != context["candidate_version_id"]
                or any(
                    result[k] is not True
                    for k in ("baseline_matched", "authentication_verified", "previous_password_rejected")
                )
                or any(
                    result[k] is not False
                    for k in ("login_enabled", "credentials_activated", "recovery_authorized")
                )
                or type(result["active_sessions"]) is not int
                or result["active_sessions"] != 0
                or not isinstance(result["previous_version_id"], str)
                or not re.fullmatch(r"[A-Za-z0-9-]{32,64}", result["previous_version_id"])
            ):
                raise ValueError("Exact registered baseline and authentication verification receipt required")
            current = guard()
            completed = {
                **intent,
                "phase": "verified_restricted",
                "verified_at": self.clock(),
                "receipt": deepcopy(result),
            }
            self.writer.patch(principal, job_id, current.revision, {FIELD: completed})
            return deepcopy(completed)
        except Exception:  # noqa: BLE001 -- preserve intent and never disclose Secret/SQL diagnostics
            try:
                current = guard()
                self.writer.patch(
                    principal, job_id, current.revision, {FIELD: {**intent, "phase": "needs_attention"}}
                )
            except Exception:  # noqa: BLE001,S110 -- uncertain state must not trigger replay
                pass
            raise OSError(
                "Database verification incomplete; inspect restrictions and never replay activation"
            ) from None
