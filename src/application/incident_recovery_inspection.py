"""Inspect persisted recovery outcomes, including lost final-commit acknowledgements.

No provider observation, authority grant, execution, compensation or state repair.
A recorded completion is a database fact, not evidence of current runtime health.
"""

import re
from datetime import datetime, timedelta

from application.deployment_writes import DeploymentMetadataWriter
from application.incident_recovery import FIELD
from application.security_hold import security_hold_projection, validate_release_request
from domain.access import Principal, Role
from ports.state import RecordConflict


class IncidentRecoveryInspection:
    def __init__(self, records, *, clock, revalidate):
        self.writer = DeploymentMetadataWriter(records)
        self.clock, self.revalidate = clock, revalidate

    def _snapshot(self, principal, job_id, revision):
        if (
            not isinstance(principal, Principal)
            or principal.role is not Role.ADMIN
            or self.revalidate() != principal
        ):
            raise PermissionError("Current organization administrator required")
        snapshot = self.writer.snapshot(principal, job_id)
        if snapshot.revision != revision:
            raise RecordConflict("Deployment changed since recovery inspection request")
        return snapshot

    def inspect(self, principal, job_id, *, recovery_id, incident_id, expected_boundary, expected_revision):
        started = self.clock()
        validate_release_request(
            incident_id, "recovery-inspection", expected_revision, expected_boundary, started
        )
        if not isinstance(recovery_id, str) or not re.fullmatch(r"[a-f0-9]{32}", recovery_id):
            raise ValueError("Exact recovery identity required")
        snapshot = self._snapshot(principal, job_id, expected_revision)
        job = snapshot.record
        history = job.get("security_incident_history", [])
        if not isinstance(history, list) or len(history) > 10:
            raise ValueError("Bounded recovery history required")
        ids = [a.get("id") if isinstance(a, dict) else None for a in history]
        if any(not isinstance(i, str) or not re.fullmatch(r"[a-f0-9]{32}", i) for i in ids) or len(
            set(ids)
        ) != len(ids):
            raise ValueError("Unambiguous recovery history required")
        active = job.get(FIELD)
        if active is not None and not isinstance(active, dict):
            raise ValueError("Valid active recovery record required")
        matches = [a for a in history if a["id"] == recovery_id]
        current = isinstance(active, dict) and active.get("id") == recovery_id
        if current and matches:
            raise ValueError("Recovery cannot be active and archived together")
        if not current and not matches:
            raise FileNotFoundError("Recovery record not found")
        if current:
            record = active
            hold = security_hold_projection(job, include_details=True)
            if (
                hold.get("record_valid") is not True
                or not isinstance(hold.get("hold"), dict)
                or not isinstance(job.get("security_review_boundary"), dict)
                or hold["hold"]["incident_id"] != incident_id
                or job.get("security_review_boundary", {}).get("id") != expected_boundary
            ):
                raise ValueError("Active recovery differs from held incident")
            outcome = {
                "approved": "approval_recorded",
                "running": "execution_outcome_unconfirmed",
                "verified": "completion_not_recorded",
                "needs_attention": "needs_attention",
            }.get(record.get("phase"))
            if outcome is None:
                raise ValueError("Recognized recovery phase required")
        else:
            archive = matches[0]
            controls = archive.get("controls")
            if not isinstance(controls, dict):
                raise ValueError("Completed recovery controls required")
            record = controls.get(FIELD)
            if (
                archive.get("incident_id") != incident_id
                or archive.get("prior_boundary") != expected_boundary
                or not isinstance(record, dict)
                or record.get("phase") != "verified"
            ):
                raise ValueError("Completed recovery archive differs from requested incident")
            recovered = timestamp(archive.get("recovered_at"))
            boundary = archive.get("new_boundary")
            if (
                not isinstance(boundary, dict)
                or set(boundary) != {"id", "recorded_at"}
                or not isinstance(boundary["id"], str)
                or not re.fullmatch(r"[a-f0-9]{32}", boundary["id"])
                or timestamp(boundary["recorded_at"]) != recovered
            ):
                raise ValueError("Recorded completion boundary required")
            outcome = "completion_recorded"
        if (
            type(record.get("version")) is not int
            or record["version"] != 1
            or (record.get("id"), record.get("incident_id"), record.get("boundary_id"))
            != (recovery_id, incident_id, expected_boundary)
        ):
            raise ValueError("Exact recovery record scope required")
        approved, expires = timestamp(record.get("approved_at")), timestamp(record.get("expires_at"))
        if not approved < expires <= approved + timedelta(seconds=900):
            raise ValueError("Bounded recorded recovery approval required")
        phase = record["phase"]
        if phase == "approved" and "external_pending" in record:
            raise ValueError("Unused approval cannot contain execution state")
        if phase != "approved" and type(record.get("external_pending")) is not bool:
            raise ValueError("Persisted external request state required")
        if phase == "running" and record["external_pending"] is not True:
            raise ValueError("Running recovery requires pending request evidence")
        if phase == "verified":
            result, plan = record.get("result"), record.get("plan")
            if (
                record["external_pending"] is not False
                or not isinstance(result, dict)
                or not isinstance(plan, dict)
                or not isinstance(plan.get("image"), str)
                or result.get("image") != plan["image"]
                or not isinstance(result.get("verification"), dict)
                or result["verification"].get("http") != "verified"
                or result["verification"].get("database_authentication") != "verified"
            ):
                raise ValueError("Persisted verified candidate result required")
            if not current and not approved <= recovered <= expires:
                raise ValueError("Recorded completion outside approval lifetime")
        checked = timestamp(self.clock())
        if approved > checked or (not current and recovered > checked):
            raise ValueError("Recovery observation cannot precede recorded events")
        if not timestamp(started) <= checked <= timestamp(started) + timedelta(seconds=300):
            raise ValueError("Fresh recovery metadata observation required")
        if self._snapshot(principal, job_id, expected_revision) != snapshot:
            raise RecordConflict("Recovery changed during inspection")
        return {
            "recovery_id": recovery_id,
            "incident_id": incident_id,
            "boundary_id": expected_boundary,
            "metadata_revision": expected_revision,
            "observed_at": checked.isoformat(),
            "persisted_phase": phase,
            "persisted_outcome": outcome,
            "completion_recorded": not current,
            "approval_expired": checked >= expires,
            "active_hold_recorded": job.get("security_hold") is not None,
            "current_result_matches_record": phase == "verified" and job.get("result") == record["result"],
            "external_pending_recorded": record.get("external_pending", False),
            "evidence_source": "persisted_metadata",
            "live_runtime_verified": False,
            "approval_authorization_checked": False,
            "recovery_authorized": False,
            "automatic_retry_allowed": False,
            "read_only": True,
            "state_changed": False,
        }


def timestamp(value):
    if not isinstance(value, str):
        raise TypeError("Recorded timezone-aware timestamp required")
    result = datetime.fromisoformat(value)
    if result.tzinfo is None:
        raise ValueError("Recorded timezone-aware timestamp required")
    return result
