"""Owned operating-loop projection and explicitly registered control boundaries.

Reads never recover a lease, inspect AWS, collect telemetry or authorize replay.
Recovery implementations are trusted composition dependencies, not browser data.
"""

from uuid import UUID

from domain.access import Action, Principal, Role, owner_from_record, permitted
from ports.state import RecordConflict

_STAGES = frozenset(
    {
        "target_prepared",
        "target_outcome_uncertain",
        "target_evidence_mismatch",
        "revalidation_after_external_effect",
        "source_read_unavailable",
        "cutover_source_unavailable",
        "quiesce",
        "fence_source",
        "fence_target",
        "final_sync",
        "activate_target",
        "probe_target",
        "enable_target",
        "resume_target",
        "publish_target_runtime",
        "quiesce_target",
        "reverse_sync",
        "activate_source",
        "probe_source",
        "resume_source",
        "runtime_deployed",
        "image_verified",
    }
)


class OperatingLifecycle:
    def __init__(
        self, reads, *, reviews=None, operations=None, preparation=None, cutover=None, recovery=None
    ):
        self.reads, self.reviews, self.operations = reads, reviews, operations
        self.preparation, self.cutover, self.recovery = preparation, cutover, recovery

    def _snapshot(self, principal, job_id):
        if not isinstance(principal, Principal):
            raise PermissionError("Verified membership required")
        value = self.reads.lifecycle(principal.organization_id, job_id)
        if value is None or not permitted(principal, Action.READ, owner_from_record(value.deployment.job)):
            raise FileNotFoundError("Deployment not found")
        if value.deployment.job.get("id") != job_id:
            raise ValueError("Deployment identity changed")
        return value

    def detail(self, principal, job_id):
        snapshot = self._snapshot(principal, job_id)
        job = snapshot.deployment.job
        from application.security_hold import require_no_security_hold

        try:
            require_no_security_hold(job)
            held = False
        except ValueError:
            held = True
        operations = []
        for item in snapshot.operations:
            operation = {key: item[key] for key in ("id", "kind", "status", "external_pending", "created_at")}
            operation["stage"] = item.get("stage") if item.get("stage") in _STAGES else None
            blocked = item["status"] == "needs_attention"
            operation.update(
                requires_attention=blocked,
                next_action="inspect_existing_result"
                if blocked
                else "observe"
                if item["status"] in {"queued", "running"}
                else "none",
                blind_retry_allowed=False,
                recovery_enabled=bool(
                    not held
                    and blocked
                    and item["kind"] == "db_dedicated_prepare"
                    and self.recovery is not None
                    and principal.role is Role.ADMIN
                ),
            )
            if principal.role is Role.ADMIN:
                operation.update(attempt_id=item["attempt_id"], row_version=item["row_version"])
            operations.append(operation)
        proposal = job.get("operating_proposal")
        proposal_status = proposal.get("status") if isinstance(proposal, dict) else None
        promotion = job.get("database_promotion")
        effect = job.get("promotion_effect_review")
        # The stored review is historical; a subsequent runtime/source change
        # must not turn an old healthy result into current operational evidence.
        from application.operating_review import deployment_observation_binding

        current_binding = deployment_observation_binding(job)
        effect_current = isinstance(effect, dict) and effect.get("deployment_binding") == current_binding
        phase = (
            "security_hold"
            if held
            else "needs_attention"
            if any(x["requires_attention"] for x in operations)
            else "executing"
            if any(x["status"] in {"queued", "running"} for x in operations)
            else "observed"
            if effect_current
            else "effect_review_required"
            if isinstance(promotion, dict)
            else "approved"
            if proposal_status == "approved"
            else "approval_required"
            if proposal_status
            else "observing"
        )
        deployer = permitted(principal, Action.DEPLOY, owner_from_record(job)) and not held
        performance = job.get("promotion_performance_review")
        public_performance = None
        if isinstance(performance, dict) and performance.get("deployment_binding") == current_binding:
            public_performance = {
                key: performance.get(key)
                for key in (
                    "status",
                    "scope",
                    "outcome",
                    "reason",
                    "reviewed_at",
                    "p95_change_percent",
                    "before_error_rate",
                    "after_error_rate",
                    "causal_improvement_proven",
                    "production_capacity_proven",
                    "application_image_compared",
                    "automatic_action",
                )
            }
            for phase in ("before", "after"):
                if isinstance(performance.get(phase), dict):
                    public_performance[phase] = {
                        key: performance[phase].get(key)
                        for key in (
                            "samples",
                            "successes",
                            "failures",
                            "concurrency",
                            "p50_ms",
                            "p95_ms",
                            "duration_seconds",
                            "throughput_rps",
                            "started_at",
                            "finished_at",
                            "evidence_ref",
                        )
                    }
        return {
            "job_id": job_id,
            "application_id": job.get("application_id", job_id),
            "revision": snapshot.deployment.revision,
            "phase": phase,
            "database_role": (job.get("workload_database_binding") or {}).get("role"),
            "proposal_status": proposal_status,
            "proposal_id": proposal.get("proposal_id") if isinstance(proposal, dict) else None,
            "operations": operations,
            "has_more_operations": snapshot.has_more,
            "effect": (
                {
                    key: effect.get(key)
                    for key in (
                        "reviewed_at",
                        "decision",
                        "placement",
                        "http_health",
                        "performance_improvement",
                        "data_read_path",
                        "automatic_action",
                        "automation_reenabled",
                    )
                }
                if effect_current
                else None
            ),
            "performance": public_performance,
            "capabilities": {
                "review": bool(deployer and self.reviews and job_id in self.reviews.policies),
                "prepare": bool(deployer and self.preparation and self.preparation.admission.enabled),
                "cutover": bool(
                    deployer and self.cutover and self.cutover.detail(principal, job_id)["execution_enabled"]
                ),
                "effect_review": bool(deployer and self.reviews and self.operations and promotion),
            },
            "automatic_action": False,
            "observed_only": True,
        }

    def review_effect(self, principal, job_id, operation_id):
        snapshot = self._snapshot(principal, job_id)
        if not permitted(principal, Action.DEPLOY, owner_from_record(snapshot.deployment.job)):
            raise PermissionError("Effect review write access denied")
        if self.reviews is None or self.operations is None:
            raise ValueError("Effect review is not configured")
        return self.reviews.review_effect(principal, job_id, operation_id, self.operations)

    def resume_preparation(self, principal, job_id, operation_id, attempt_id, row_version):
        snapshot = self._snapshot(principal, job_id)
        if principal.role is not Role.ADMIN:
            raise PermissionError("Current administrator required")
        from application.security_hold import require_no_security_hold

        require_no_security_hold(snapshot.deployment.job)
        UUID(operation_id)
        UUID(attempt_id)
        if type(row_version) is not int or not 1 <= row_version < 2**63:
            raise ValueError("Original operation version required")
        expected = next((x for x in snapshot.operations if x["id"] == operation_id), None)
        if expected is None:
            raise FileNotFoundError("Preparation operation not found")
        if (expected["kind"], expected["status"], expected["attempt_id"], expected["row_version"]) != (
            "db_dedicated_prepare",
            "needs_attention",
            attempt_id,
            row_version,
        ):
            raise RecordConflict("Original blocked snapshot changed; inspect it again")
        if self.recovery is None:
            raise ValueError("Trusted executor exclusion and target observer are not configured")
        # This service reauthorizes the operator, excludes the old executor,
        # observes the exact existing target, then performs CAS + durable outbox.
        return self.recovery.resume(principal, operation_id, attempt_id, row_version)
