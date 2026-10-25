"""Observe a held deployment without clearing its hold or admitting recovery."""

from copy import deepcopy
from datetime import datetime, timedelta

from application.deployment_writes import DeploymentMetadataWriter
from application.security_hold import security_hold_projection, validate_release_request
from domain.access import Principal, Role
from domain.incident_runtime import runtime_identity
from ports.incident_runtime import IncidentRuntimeInspection as RuntimePort
from ports.state import RecordConflict


class IncidentRuntimeInspection:
    def __init__(self, records, runtime: RuntimePort, *, clock, revalidate):
        self.writer, self.runtime = DeploymentMetadataWriter(records), runtime
        self.clock, self.revalidate = clock, revalidate

    def inspect(self, principal, job_id, *, incident_id, expected_boundary, expected_revision):
        started = self.clock()
        validate_release_request(
            incident_id, "runtime-inspection", expected_revision, expected_boundary, started
        )

        def snapshot():
            value = self._scope(principal, job_id, incident_id, expected_boundary, started)
            if value.revision != expected_revision:
                raise RecordConflict("Deployment changed since runtime inspection request")
            return value

        original = snapshot()

        def guard():
            if snapshot() != original:
                raise RecordConflict("Deployment changed during runtime inspection")

        try:
            guard()
            _, _, cluster, arn, _, task_prefix, known = runtime_identity(original.record.get("result"))
            result = self.runtime.inspect(deepcopy(original.record.get("result")), guard=guard)
            checked = datetime.fromisoformat(self.clock())
            beginning = datetime.fromisoformat(started)
            if (
                not isinstance(result, dict)
                or set(result)
                != {
                    "service_arn",
                    "cluster_arn",
                    "task_arns",
                    "registered_service_quiescent",
                    "read_only",
                    "execution_exclusion_verified",
                    "scheduler_fenced",
                    "state_changed",
                }
                or result["service_arn"] != arn
                or result["cluster_arn"] != cluster
                or not isinstance(result["task_arns"], list)
                or not 1 <= len(result["task_arns"]) <= 100
                or any(
                    not isinstance(task, str) or not task.startswith(task_prefix)
                    for task in result["task_arns"]
                )
                or len(set(result["task_arns"])) != len(result["task_arns"])
                or not set(known).issubset(result["task_arns"])
                or type(result["registered_service_quiescent"]) is not bool
                or result["read_only"] is not True
                or any(
                    result[key] is not False
                    for key in ("execution_exclusion_verified", "scheduler_fenced", "state_changed")
                )
                or checked.tzinfo is None
                or not beginning <= checked <= beginning + timedelta(seconds=300)
            ):
                raise ValueError("Exact read-only runtime observation required")
            guard()
        except (PermissionError, RecordConflict):
            raise
        except Exception:  # noqa: BLE001 -- never return native diagnostics or credentials
            raise OSError("Runtime inspection unavailable; hold and access remain unchanged") from None
        return {
            "incident_id": incident_id,
            "boundary_id": expected_boundary,
            "metadata_revision": expected_revision,
            "observed_at": checked.isoformat(),
            **deepcopy(result),
            "recovery_authorized": False,
        }

    def _scope(self, principal, job_id, incident_id, expected_boundary, started):
        if (
            not isinstance(principal, Principal)
            or principal.role is not Role.ADMIN
            or self.revalidate() != principal
        ):
            raise PermissionError("Current organization administrator required")
        value = self.writer.snapshot(principal, job_id)
        projection = security_hold_projection(value.record, include_details=True)
        if (
            projection.get("record_valid") is not True
            or projection["hold"]["incident_id"] != incident_id
            or value.record.get("security_review_boundary")
            != {"id": expected_boundary, "recorded_at": projection["hold"]["recorded_at"]}
        ):
            raise ValueError("Current incident hold and boundary required")
        if datetime.fromisoformat(started) < datetime.fromisoformat(projection["hold"]["recorded_at"]):
            raise ValueError("Observation cannot precede incident")
        return value
