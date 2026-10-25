"""Incident-bound read-only task observation; no backfill or operation resolution."""

from copy import deepcopy
from datetime import datetime, timedelta

from application.incident_credential_preparation import FIELD, preparation_record_is_valid
from application.incident_runtime_inspection import IncidentRuntimeInspection
from application.security_hold import validate_release_request
from ports.state import RecordConflict


class CredentialExecutorInspection:
    def __init__(self, records, observer, *, clock, revalidate):
        self.scope = IncidentRuntimeInspection(records, None, clock=clock, revalidate=revalidate)
        self.observer, self.clock = observer, clock

    def inspect(
        self, principal, job_id, *, incident_id, expected_boundary, expected_revision, expected_operation_id
    ):
        started = self.clock()
        validate_release_request(
            incident_id, "credential-executor", expected_revision, expected_boundary, started
        )
        snapshot = self.scope._scope(principal, job_id, incident_id, expected_boundary, started)
        record = snapshot.record.get(FIELD)
        if (
            not preparation_record_is_valid(record)
            or record["operation_id"] != expected_operation_id
            or record["incident_id"] != incident_id
            or record["boundary_id"] != expected_boundary
            or record["binding"] != snapshot.record.get("workload_database_binding")
            or record["binding"]["organization_id"] != principal.organization_id
            or record["binding"]["application_id"] != snapshot.record.get("application_id")
            or datetime.fromisoformat(started) < datetime.fromisoformat(record["requested_at"])
        ):
            raise ValueError("Exact current credential preparation required")
        if snapshot.revision != expected_revision:
            raise RecordConflict("Deployment changed since executor inspection request")

        def guard():
            if self.scope._scope(principal, job_id, incident_id, expected_boundary, started) != snapshot:
                raise RecordConflict("Incident or preparation changed during executor inspection")

        executor = record.get("executor")
        receipt = {
            "task_arn": None,
            "executor_state": "not_recorded",
            "stopped_at": None,
            "observed_at": started,
            "provider_requests_settled": False,
            "execution_exclusion_verified": False,
            "recovery_authorized": False,
            "state_changed": False,
            "read_only": True,
        }
        try:
            guard()
            if executor is not None:
                receipt = self.observer.observe(
                    deepcopy(executor),
                    account_id=record["binding"]["account_id"],
                    region=record["binding"]["region"],
                    requested_at=record["requested_at"],
                    guard=guard,
                )
                if (
                    not isinstance(receipt, dict)
                    or set(receipt)
                    != {
                        "task_arn",
                        "executor_state",
                        "stopped_at",
                        "observed_at",
                        "provider_requests_settled",
                        "execution_exclusion_verified",
                        "recovery_authorized",
                        "state_changed",
                        "read_only",
                    }
                    or receipt["task_arn"] != executor["task_arn"]
                    or receipt["read_only"] is not True
                    or receipt["executor_state"] not in {"stopped", "not_stopped", "unavailable"}
                    or any(
                        receipt[key] is not False
                        for key in (
                            "provider_requests_settled",
                            "execution_exclusion_verified",
                            "recovery_authorized",
                            "state_changed",
                        )
                    )
                ):
                    raise ValueError("Exact read-only executor receipt required")
                if receipt["executor_state"] == "stopped":
                    stopped = datetime.fromisoformat(receipt["stopped_at"])
                    if stopped.tzinfo is None or not datetime.fromisoformat(
                        record["requested_at"]
                    ) <= stopped <= datetime.fromisoformat(receipt["observed_at"]):
                        raise ValueError("Verified original task stop time required")
                elif receipt["stopped_at"] is not None:
                    raise ValueError("Unverified task cannot include a stop timestamp")
            checked, completed = (
                datetime.fromisoformat(receipt["observed_at"]),
                datetime.fromisoformat(self.clock()),
            )
            if (
                checked.tzinfo is None
                or completed.tzinfo is None
                or not datetime.fromisoformat(started)
                <= checked
                <= completed
                <= datetime.fromisoformat(started) + timedelta(seconds=300)
            ):
                raise ValueError("Fresh executor observation required")
            guard()
        except (PermissionError, RecordConflict):
            raise
        except Exception:  # noqa: BLE001 -- no provider diagnostics in operator output
            raise OSError(
                "Executor inspection unavailable; no preparation or access change requested"
            ) from None
        return {
            "operation_id": expected_operation_id,
            "metadata_revision": snapshot.revision,
            "persisted_phase": record["phase"],
            **deepcopy(receipt),
        }
