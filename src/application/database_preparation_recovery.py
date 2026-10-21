"""Explicit trusted reconciliation of an available dedicated preparation target.

No runtime, HTTP or CLI enables this service. A real recovery authority must
first implement the executor exclusion port; read-only observation alone cannot
release the original application reservation. Unknown/absent targets stay blocked.
"""

import hashlib
import json
import re

from application.database_promotion_workflow import KIND, PromotionPreparationWorker, safe_target_receipt
from application.deployment_writes import DeploymentMetadataWriter
from domain.access import Principal, Role
from ports.preparation_recovery import PreparationRecoveryFence
from ports.state import RecordConflict


class PromotionPreparationRecovery:
    def __init__(self, records, operations, policies, observer, resolve_principal, authority, *, clock):
        self.operations, self.observer, self.authority = operations, observer, authority
        self.resolve_principal = resolve_principal
        self.validator = PromotionPreparationWorker(
            records, operations, policies, None, resolve_principal,
            owner="preparation-recovery-validation", clock=clock,
        )

    def _operator(self, principal, job_id):
        if not isinstance(principal, Principal):
            raise PermissionError("Verified recovery operator required")
        current = self.resolve_principal(principal.user_id, principal.organization_id)
        if (not isinstance(current, Principal) or current.role is not Role.ADMIN
                or current.user_id != principal.user_id
                or current.organization_id != principal.organization_id):
            raise PermissionError("Current organization administrator required")
        DeploymentMetadataWriter(self.validator.records).snapshot(current, job_id)
        return current

    def resume(self, principal, operation_id, attempt_id, expected_version):
        """Observe and enqueue a verified checkpoint; never complete or provision."""
        operation = self.operations.get(operation_id)
        if (operation.kind != KIND or operation.status != "needs_attention"
                or operation.external_pending is not True
                or operation.attempt_id != attempt_id
                or type(expected_version) is not int or operation.row_version != expected_version):
            raise RecordConflict("Original blocked preparation snapshot required")
        job_id = operation.command.get("job_id")
        operator = self._operator(principal, job_id)
        plan = self.validator._validate(operation)
        intent = {"kind": KIND, "operation_id": operation.id,
                  "plan_id": plan["plan_id"], "target": plan["target"]}
        if operation.external_intent != intent:
            raise ValueError("Original preparation intent differs from the approved plan")
        if self.authority is None:
            raise ValueError("Trusted executor recovery authority is not configured")
        with self.authority.hold(operation) as fence:
            if (not isinstance(fence, PreparationRecoveryFence)
                    or (fence.workspace, fence.operation_id, fence.attempt_id, fence.row_version)
                    != (self.operations.workspace, operation.id, operation.attempt_id, operation.row_version)
                    or not isinstance(fence.evidence_ref, str)
                    or not re.fullmatch(r"evidence:[A-Za-z0-9/_-]{1,200}", fence.evidence_ref)
                    or not callable(fence.check)):
                raise ValueError("Scoped executor exclusion evidence required")

            def guard():
                fence.check()
                self._operator(principal, job_id)
                if self.operations.get(operation.id) != operation:
                    raise RecordConflict("Preparation changed during recovery")
                if self.validator._validate(operation) != plan:
                    raise RecordConflict("Approved recovery plan changed")
                fence.check()

            guard()
            receipt = self.observer.observe(plan, operation_id=operation.id, guard=guard)
            safe = safe_target_receipt(receipt, plan, operation.id)
            guard()
            actor = {"organization_id": operator.organization_id, "user_id": operator.user_id}
            resolver = "recovery-" + hashlib.sha256(
                json.dumps(actor, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            # CAS atomically retains scope and records a new attempt/outbox. A
            # lost commit response propagates: do not repeat observer or mutation.
            saved = self.operations.resolve_attention(
                operation.id, operation.attempt_id, operation.row_version, intent,
                {**safe, "executor_exclusion_evidence_ref": fence.evidence_ref, "recovery_operator": actor},
                {"stage": "target_prepared"},
                resolver=resolver, outcome="resume",
            )
            if not saved:
                raise RecordConflict("Preparation resolution snapshot changed")
        return {"operation_id": operation.id, "status": "queued",
                "scope": "dedicated_target_preparation_only", "data_routing_changed": False}
