"""Post-change observations: verify placement and health without inventing benefit.

This is a trusted internal review over stored, deployment-bound probes. It does
not accept browser metrics, re-enable consent, initiate a rollback or claim that
moving a DB improved performance. Missing evidence stays inconclusive.
"""

from copy import deepcopy
from datetime import datetime

from application.deployment_writes import DeploymentMetadataWriter
from application.operating_review import deployment_observation_binding
from application.security_hold import require_no_security_hold
from domain.database import DatabaseBinding


class PromotionEffectReview:
    def __init__(self, records, operations):
        self.writer, self.operations = DeploymentMetadataWriter(records), operations

    def review(self, principal, job_id, operation_id, *, now, max_health_age_seconds=300):
        current = datetime.fromisoformat(now)
        if (
            current.tzinfo is None
            or type(max_health_age_seconds) is not int
            or not 1 <= max_health_age_seconds <= 3600
        ):
            raise ValueError("Bounded timezone-aware effect review required")
        snapshot = self.writer.snapshot(principal, job_id)
        job = snapshot.record
        require_no_security_hold(job)
        projection = job.get("database_promotion")
        operation = self.operations.get(operation_id)
        if (
            not isinstance(projection, dict)
            or projection.get("operation_id") != operation_id
            or operation.kind != "db_dedicated_cutover"
            or operation.status != "succeeded"
            or operation.application_id != job["application_id"]
            or operation.result != projection
            or projection.get("binding") != job.get("workload_database_binding")
            or projection.get("active_runtime") is None
        ):
            raise ValueError("Exact completed and published promotion required")
        target = DatabaseBinding(**projection["binding"])
        source = DatabaseBinding(**projection["baseline"]["source"])
        active = projection["active_runtime"]
        if (
            target.role != "dedicated_workload"
            or source.role != "shared_workload"
            or source.instance_id == target.instance_id
            or active.get("database", {}).get("binding") != projection["binding"]
            or any(job["result"].get(key) != active.get(key) for key in ("service_arn", "image", "url"))
            or active.get("verification", {}).get("stable_route") != "verified"
        ):
            raise ValueError("Active runtime or physical placement changed after promotion")
        health = self.writer.health_snapshot(principal, job_id)
        latest = health.record[-1] if health and health.record else None
        fresh = False
        if isinstance(latest, dict) and latest.get("deployment_binding") == deployment_observation_binding(
            job
        ):
            checked = datetime.fromisoformat(latest["checked_at"])
            fresh = (
                checked.tzinfo is not None
                and 0 <= (current - checked).total_seconds() <= max_health_age_seconds
            )
        healthy = latest.get("healthy") if fresh else None
        report = {
            "operation_id": operation_id,
            "reviewed_at": now,
            "deployment_binding": deployment_observation_binding(job),
            "target_binding": deepcopy(projection["binding"]),
            "placement": "dedicated_instance_verified",
            "http_health": "verified" if healthy is True else "failed" if healthy is False else "unverified",
            "decision": "retain_and_observe"
            if healthy is True
            else "recovery_review_required"
            if healthy is False
            else "insufficient_evidence",
            "performance_improvement": "unverified",
            "data_read_path": active.get("verification", {}).get("application_data_path", "unverified"),
            "automatic_action": False,
            "automation_reenabled": False,
        }
        self.writer.patch(principal, job_id, snapshot.revision, {"promotion_effect_review": report})
        return report
