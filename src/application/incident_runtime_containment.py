"""Durable, non-replayed service scale-down; all recovery gates remain closed."""

import re
from copy import deepcopy
from datetime import datetime, timedelta
from uuid import uuid4

from application.incident_runtime_inspection import IncidentRuntimeInspection
from application.security_hold import validate_release_request
from domain.incident_containment import target_after_request, validate_containment_target
from domain.incident_runtime import runtime_identity
from ports.incident_containment import IncidentRuntimeContainment as ContainmentPort
from ports.state import RecordConflict

FIELD = "security_runtime_containment"


class IncidentRuntimeContainment:
    def __init__(self, records, runtime: ContainmentPort, *, clock, revalidate):
        self.scope = IncidentRuntimeInspection(records, None, clock=clock, revalidate=revalidate)
        self.writer, self.runtime, self.clock = self.scope.writer, runtime, clock

    def status(self, principal, job_id):
        from domain.access import Principal, Role

        if (
            not isinstance(principal, Principal)
            or principal.role is not Role.ADMIN
            or self.scope.revalidate() != principal
        ):
            raise PermissionError("Current organization administrator required")
        snapshot = self.writer.snapshot(principal, job_id)
        record = snapshot.record.get(FIELD)
        if record is None:
            return {"phase": "not_recorded"}
        if not containment_record_is_valid(record, snapshot.record.get("result")):
            return {"phase": "needs_attention", "record_valid": False}
        return {**deepcopy(record), "record_valid": True}

    def _scope(self, principal, job_id, incident_id, expected_boundary, now):
        return self.scope._scope(principal, job_id, incident_id, expected_boundary, now)

    def request(self, principal, job_id, *, incident_id, expected_boundary, expected_revision):
        now = self.clock()
        validate_release_request(
            incident_id, "runtime-containment", expected_revision, expected_boundary, now
        )
        snapshot = self._scope(principal, job_id, incident_id, expected_boundary, now)
        result = snapshot.record.get("result")
        runtime_identity(result)
        previous = snapshot.record.get(FIELD)
        if previous is not None:
            if containment_record_is_valid(previous, result) and all(
                previous[key] == value
                for key, value in {
                    "incident_id": incident_id,
                    "boundary_id": expected_boundary,
                    "admitted_revision": expected_revision,
                    "requested_by": principal.user_id,
                }.items()
            ):
                return deepcopy(previous)  # including uncertain intents: never replay
            raise ValueError("Existing runtime containment requires operator inspection")
        if snapshot.revision != expected_revision:
            raise RecordConflict("Deployment changed since containment request")

        def admission_guard():
            if self._scope(principal, job_id, incident_id, expected_boundary, now) != snapshot:
                raise RecordConflict("Incident changed during containment preflight")

        try:
            target = self.runtime.preflight(deepcopy(result), guard=admission_guard)
            validate_containment_target(target, result)
            admission_guard()
        except (PermissionError, RecordConflict):
            raise
        except Exception:  # noqa: BLE001 -- native metadata/errors must not leak
            raise OSError("Runtime containment preflight unavailable; no mutation requested") from None
        intent = {
            "schema_version": 1,
            "operation_id": uuid4().hex,
            "incident_id": incident_id,
            "boundary_id": expected_boundary,
            "admitted_revision": expected_revision,
            "requested_by": principal.user_id,
            "requested_at": now,
            "target": deepcopy(target),
            "phase": "applying",
        }
        if not containment_record_is_valid(intent, result):
            raise ValueError("Exact runtime containment intent required")
        try:
            admitted = self.writer.patch(
                principal,
                job_id,
                expected_revision,
                {
                    FIELD: intent,
                    "promotion_automation_consent": None,
                },
            )
        except OSError:
            raise OSError(
                "Containment admission uncertain; inspect persisted intent before proceeding"
            ) from None

        def guard():
            current = self._scope(principal, job_id, incident_id, expected_boundary, now)
            if (
                current.revision != admitted.revision
                or current.record.get(FIELD) != intent
                or current.record.get("result") != result
                or current.record.get("security_hold") != snapshot.record.get("security_hold")
            ):
                raise RecordConflict("Runtime containment execution ownership changed")
            return current

        try:
            guard()
            observed = self.runtime.request(deepcopy(result), deepcopy(target), guard=guard)
            if observed != target_after_request(target):
                raise ValueError("Exact scaling suspension and zero desired count required")
            completed = {
                **intent,
                "phase": "scale_down_requested",
                "acknowledged_at": self.clock(),
                "observed_target": deepcopy(observed),
            }
            if not containment_record_is_valid(completed, result):
                raise ValueError("Invalid containment acknowledgement")
            current = guard()
            self.writer.patch(principal, job_id, current.revision, {FIELD: completed})
            return deepcopy(completed)
        except Exception:  # noqa: BLE001 -- retain uncertainty; never compensate by restoring scaling
            try:
                current = guard()
                self.writer.patch(
                    principal,
                    job_id,
                    current.revision,
                    {
                        FIELD: {
                            **intent,
                            "phase": "needs_attention",
                            "failure_code": "outcome_unconfirmed",
                        }
                    },
                )
            except Exception:  # noqa: BLE001,S110 -- the original applying intent is also blocking
                pass
            raise OSError("Containment outcome needs inspection; no automatic retry or resume") from None

    def inspect(
        self, principal, job_id, *, incident_id, expected_boundary, expected_revision, expected_operation_id
    ):
        started = self.clock()
        validate_release_request(
            incident_id, "containment-inspection", expected_revision, expected_boundary, started
        )
        snapshot = self._scope(principal, job_id, incident_id, expected_boundary, started)
        record, result = snapshot.record.get(FIELD), snapshot.record.get("result")
        if (
            not containment_record_is_valid(record, result)
            or record["operation_id"] != expected_operation_id
            or record["incident_id"] != incident_id
            or record["boundary_id"] != expected_boundary
        ):
            raise ValueError("Exact current runtime containment operation required")
        if datetime.fromisoformat(started) < datetime.fromisoformat(record["requested_at"]):
            raise ValueError("Containment observation cannot precede its intent")
        if snapshot.revision != expected_revision:
            raise RecordConflict("Deployment changed since containment inspection request")

        def guard():
            if self._scope(principal, job_id, incident_id, expected_boundary, started) != snapshot:
                raise RecordConflict("Incident changed during containment inspection")

        try:
            guard()
            observed = self.runtime.inspect(deepcopy(result), deepcopy(record["target"]), guard=guard)
            validate_containment_target(observed, result)
            allowed = {
                **observed,
                "min_capacity": record["target"]["min_capacity"],
                "desired_count": record["target"]["desired_count"],
                "suspended_state": record["target"]["suspended_state"],
            }
            if allowed != record["target"] or observed["min_capacity"] not in {
                0,
                record["target"]["min_capacity"],
            }:
                raise ValueError("Containment observation identity changed")
            checked = datetime.fromisoformat(self.clock())
            beginning = datetime.fromisoformat(started)
            if checked.tzinfo is None or not beginning <= checked <= beginning + timedelta(seconds=300):
                raise ValueError("Fresh containment observation required")
            guard()
        except (PermissionError, RecordConflict):
            raise
        except Exception:  # noqa: BLE001 -- never leak native errors or normalize an uncertain phase
            raise OSError("Containment inspection unavailable; no mutation requested") from None
        return {
            "operation_id": expected_operation_id,
            "metadata_revision": snapshot.revision,
            "persisted_phase": record["phase"],
            "observed_at": checked.isoformat(),
            "scale_down_configuration_observed": observed == target_after_request(record["target"]),
            "observed_target": deepcopy(observed),
            "read_only": True,
            "state_changed": False,
            "scheduler_fenced": False,
            "execution_exclusion_verified": False,
            "recovery_authorized": False,
        }


def containment_record_is_valid(record, result):
    base = {
        "schema_version",
        "operation_id",
        "incident_id",
        "boundary_id",
        "admitted_revision",
        "requested_by",
        "requested_at",
        "target",
        "phase",
    }
    extra = {
        "applying": set(),
        "needs_attention": {"failure_code"},
        "scale_down_requested": {"acknowledged_at", "observed_target"},
    }
    try:
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("phase"), str)
            or record["phase"] not in extra
        ):
            return False
        if (
            set(record) != base | extra[record["phase"]]
            or type(record["schema_version"]) is not int
            or record["schema_version"] != 1
        ):
            return False
        validate_release_request(
            record["incident_id"],
            "runtime-containment",
            record["admitted_revision"],
            record["boundary_id"],
            record["requested_at"],
        )
        validate_containment_target(record["target"], result)
        if not isinstance(record["operation_id"], str) or not re.fullmatch(
            r"[a-f0-9]{32}", record["operation_id"]
        ):
            return False
        if not isinstance(record["requested_by"], str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", record["requested_by"]
        ):
            return False
        if record["phase"] == "needs_attention":
            return record["failure_code"] == "outcome_unconfirmed"
        if record["phase"] == "scale_down_requested":
            stamp = datetime.fromisoformat(record["acknowledged_at"])
            return (
                stamp.tzinfo is not None
                and stamp >= datetime.fromisoformat(record["requested_at"])
                and record["observed_target"] == target_after_request(record["target"])
            )
        return True
    except (ValueError, TypeError, KeyError):
        return False
