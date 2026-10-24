"""Trusted operator observation over persistent records, without hold release.

The fixed probe must verify resource ownership before HTTP access. Probe output
is availability evidence, never a security clearance. Job and health CAS writes
are separate transactions; consumers must revalidate the recorded binding.
"""

from copy import deepcopy
from datetime import datetime

from application.analysis import redact
from application.deployment_writes import DeploymentMetadataWriter
from application.operating_review import deployment_observation_binding
from domain.access import Principal, Role
from ports.state import RecordConflict


def _time(value):
    try:
        stamp = datetime.fromisoformat(value)
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise ValueError()
        return stamp
    except (TypeError, ValueError):
        raise ValueError("A timezone-aware observation time is required") from None


class DeploymentObservationRecorder:
    def __init__(self, records, probe, *, clock, revalidate):
        self.writer = DeploymentMetadataWriter(records)
        self.probe, self.clock, self.revalidate = probe, clock, revalidate

    def collect(self, principal, job_id):
        if not isinstance(principal, Principal) or principal.role is not Role.ADMIN:
            raise PermissionError("Only an organization administrator may collect recovery observations")
        if self.revalidate() != principal:
            raise PermissionError("Administrator membership changed")
        snapshot = self.writer.snapshot(principal, job_id)
        job = snapshot.record
        if (
            job.get("status") != "succeeded"
            or job.get("deployment_state", "active") != "active"
            or not isinstance(job.get("result"), dict)
            or not job["result"]
            or job.get("release_rollback_state") in {"running", "needs_attention"}
        ):
            raise ValueError("Only active settled deployments can be observed")
        binding = deployment_observation_binding(job)
        health = self.writer.health_snapshot(principal, job_id)
        started = _time(self.clock())
        try:
            result = self.probe(deepcopy(job))
        except Exception:  # noqa: BLE001 -- trusted probe failures may contain credentials
            raise OSError("Deployment observation unavailable") from None
        finished = _time(self.clock())
        if not isinstance(result, dict) or type(result.get("healthy")) is not bool:
            raise ValueError("A verified boolean health observation is required")
        checked = _time(result.get("checked_at"))
        if not started <= checked <= finished:
            raise ValueError("Probe timestamp must belong to this observation attempt")
        boundary = job.get("security_review_boundary")
        if boundary is not None and checked < _time(boundary["recorded_at"]):
            raise ValueError("A post-incident observation is required")
        reason = result.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("An observation reason is required")
        if self.revalidate() != principal:
            raise PermissionError("Administrator membership changed")
        current = self.writer.snapshot(principal, job_id)
        if current.revision != snapshot.revision:
            raise RecordConflict("Deployment changed during observation")
        observation = {
            "healthy": result["healthy"],
            "checked_at": checked.isoformat(),
            "reason": redact(reason)[:300],
            "source": "manual",
            "deployment_binding": binding,
        }
        receipt = self.writer.record_health(
            principal, job_id, health.revision if health else None, observation, retention=100
        )
        return {
            "healthy": observation["healthy"],
            "checked_at": observation["checked_at"],
            "health_revision": receipt.revision,
        }
