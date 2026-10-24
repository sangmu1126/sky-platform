"""Synchronous trusted-operator DB restriction, without automatic retry/takeover.

Persist intent before SQL. No expired lease authorizes another executor: an
applying/uncertain attempt requires separate reconciliation. Restricts only the
registered app login; it is not network quarantine or credential rotation.
"""

import re
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime
from uuid import uuid4

from application.deployment_writes import DeploymentMetadataWriter
from application.security_hold import security_hold_projection, validate_release_request
from domain.access import Principal, Role
from domain.database import DatabaseBinding
from ports.incident_database import DatabaseRestriction
from ports.state import RecordConflict

FIELD = "security_database_restriction"


class IncidentDatabaseRestriction:
    def __init__(self, records, restriction: DatabaseRestriction, *, clock, revalidate):
        self.writer = DeploymentMetadataWriter(records)
        self.restriction, self.clock, self.revalidate = restriction, clock, revalidate

    def _authorized(self, principal):
        if (
            not isinstance(principal, Principal)
            or principal.role is not Role.ADMIN
            or self.revalidate() != principal
        ):
            raise PermissionError("Current organization administrator required")

    def _scope(self, principal, job_id, incident_id, boundary):
        self._authorized(principal)
        snapshot = self.writer.snapshot(principal, job_id)
        job = snapshot.record
        status = security_hold_projection(job, include_details=True)
        if (
            status.get("record_valid") is not True
            or status["hold"]["incident_id"] != incident_id
            or job.get("security_review_boundary")
            != {"id": boundary, "recorded_at": status["hold"]["recorded_at"]}
        ):
            raise ValueError("Current incident hold and review boundary required")
        binding = self.restriction.binding
        if (
            not isinstance(binding, DatabaseBinding)
            or binding.role not in {"shared_workload", "dedicated_workload"}
            or binding.organization_id != principal.organization_id
            or binding.application_id != job.get("application_id")
            or job.get("workload_database_binding") != asdict(binding)
            or job.get("deployment_state", "active") != "active"
        ):
            raise ValueError("Registered workload database differs from the held deployment")
        return snapshot

    def status(self, principal, job_id):
        self._authorized(principal)
        snapshot = self.writer.snapshot(principal, job_id)
        record = snapshot.record.get(FIELD)
        if record is None:
            return {"phase": "not_recorded"}
        if not restriction_record_is_valid(record):
            return {"phase": "needs_attention", "record_valid": False}
        return {**deepcopy(record), "record_valid": True}

    def restrict(self, principal, job_id, *, incident_id, expected_boundary, expected_revision):
        now = self.clock()
        validate_release_request(incident_id, "restriction-intent", expected_revision, expected_boundary, now)
        snapshot = self._scope(principal, job_id, incident_id, expected_boundary)
        if datetime.fromisoformat(now) < datetime.fromisoformat(
            snapshot.record["security_hold"]["recorded_at"]
        ):
            raise ValueError("Restriction time cannot precede the incident")
        previous = snapshot.record.get(FIELD)
        if previous is not None:
            if (
                restriction_record_is_valid(previous)
                and previous.get("incident_id") == incident_id
                and previous.get("boundary_id") == expected_boundary
                and previous.get("binding") == asdict(self.restriction.binding)
                and previous.get("admitted_revision") == expected_revision
                and previous.get("requested_by") == principal.user_id
                and previous.get("phase") in {"applying", "verified", "needs_attention"}
            ):
                return deepcopy(previous)  # Never repeat an uncertain SQL mutation.
            raise ValueError("Existing database restriction requires operator reconciliation")
        if snapshot.revision != expected_revision:
            raise RecordConflict("Deployment changed since incident review")
        intent = {
            "schema_version": 1,
            "operation_id": uuid4().hex,
            "incident_id": incident_id,
            "boundary_id": expected_boundary,
            "admitted_revision": expected_revision,
            "requested_by": principal.user_id,
            "requested_at": now,
            "binding": asdict(self.restriction.binding),
            "phase": "applying",
        }
        try:
            self.writer.patch(
                principal, job_id, snapshot.revision, {FIELD: intent, "promotion_automation_consent": None}
            )
        except OSError:
            raise OSError(
                "Database restriction admission uncertain; inspect persisted intent before proceeding"
            ) from None

        def guard():
            current = self._scope(principal, job_id, incident_id, expected_boundary)
            if current.record.get(FIELD) != intent:
                raise RecordConflict("Database restriction execution ownership changed")
            return current

        try:
            guard()
            receipt = self.restriction.restrict(guard=guard)
            if receipt != {"binding": intent["binding"], "login_enabled": False}:
                raise ValueError("Database restriction did not verify its exact scope")
            verified_at = self.clock()
            stamp = datetime.fromisoformat(verified_at)
            if stamp.tzinfo is None or stamp < datetime.fromisoformat(now):
                raise ValueError("Invalid restriction verification time")
            current = guard()
            verified = {
                **intent,
                "phase": "verified",
                "verified_at": stamp.isoformat(),
                "verified_scope": "app_login_disabled_and_its_database_sessions_drained",
            }
            self.writer.patch(principal, job_id, current.revision, {FIELD: verified})
            return deepcopy(verified)
        except Exception:  # noqa: BLE001 -- preserve uncertain intent without leaking SQL credentials
            try:
                current = guard()
                self.writer.patch(
                    principal,
                    job_id,
                    current.revision,
                    {
                        FIELD: {**intent, "phase": "needs_attention", "failure_code": "outcome_unconfirmed"},
                    },
                )
            except Exception:  # noqa: BLE001, S110 -- preserve durable intent and raise a fixed error below
                pass
            raise OSError(
                "Database restriction outcome needs operator inspection; do not retry automatically"
            ) from None


def restriction_record_is_valid(value):
    base = {
        "schema_version",
        "operation_id",
        "incident_id",
        "boundary_id",
        "admitted_revision",
        "requested_by",
        "requested_at",
        "binding",
        "phase",
    }
    extras = {
        "applying": set(),
        "needs_attention": {"failure_code"},
        "verified": {"verified_at", "verified_scope"},
    }
    if not isinstance(value, dict) or not isinstance(value.get("phase"), str):
        return False
    phase = value["phase"]
    if phase not in extras or set(value) != base | extras[phase]:
        return False
    try:
        validate_release_request(
            value["incident_id"],
            "restriction-intent",
            value["admitted_revision"],
            value["boundary_id"],
            value["requested_at"],
        )
        binding = DatabaseBinding(**value["binding"])
        if (
            type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or not isinstance(value["operation_id"], str)
            or not re.fullmatch(r"[a-f0-9]{32}", value["operation_id"])
            or not isinstance(value["requested_by"], str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", value["requested_by"])
            or binding.role not in {"shared_workload", "dedicated_workload"}
        ):
            return False
        if phase == "needs_attention":
            return value["failure_code"] == "outcome_unconfirmed"
        if phase == "verified":
            stamp = datetime.fromisoformat(value["verified_at"])
            return (
                stamp.tzinfo is not None
                and stamp >= datetime.fromisoformat(value["requested_at"])
                and value["verified_scope"] == "app_login_disabled_and_its_database_sessions_drained"
            )
        return True
    except (TypeError, ValueError, KeyError):
        return False
