"""Durable dedicated-target preparation, deliberately separate from DB cutover.

No hosted runtime activates this workflow yet. Admission is explicitly disabled
until a dedicated queue, preparer and role are registered. Queue bodies supply
IDs; only the persisted, approved and revalidated plan may reach the preparer.
"""

import re
from contextlib import nullcontext

from application.operating_review import OperatingReview, require_current_cost_estimate
from domain.access import Principal
from ports.preparation_executor import EcsPreparationExecutor, validate_preparation_executor
from ports.state import RecordConflict

KIND = "db_dedicated_prepare"


def preparation_intent(plan, operation_id, executor=None):
    intent = {"kind": KIND, "operation_id": operation_id,
              "plan_id": plan["plan_id"], "target": plan["target"]}
    if executor is not None:
        intent["executor"] = validate_preparation_executor(executor)
        target = plan["target"]
        if not executor["task_arn"].startswith(
                f"arn:aws:ecs:{target['region']}:{target['account_id']}:task/"):
            raise ValueError("Executor differs from the dedicated preparation account and region")
    return intent


def approved_snapshot(records, principal, job_id, proposal_id, policy, now):
    service = OperatingReview(records)
    snapshot, expected = service._proposal(principal, job_id, policy, now)
    stored = snapshot.record.get("operating_proposal")
    if expected is None or not isinstance(stored, dict):
        raise ValueError("An approved current promotion review is required")
    approval = stored.get("approval")
    candidate = {**expected, "status": "approved", "approval": approval}
    if (stored != candidate or stored["proposal_id"] != proposal_id
            or not isinstance(approval, dict)
            or set(approval) != {"user_id", "organization_id", "approved_at", "proposal_id"}
            or approval["organization_id"] != principal.organization_id
            or approval["proposal_id"] != proposal_id):
        raise ValueError("Promotion approval changed; review again")
    require_current_cost_estimate(expected, policy, now)
    return snapshot, stored


class PromotionPreparationAdmission:
    def __init__(self, records, operations, policies, *, enabled=False, clock):
        self.records, self.operations, self.policies = records, operations, dict(policies)
        self.enabled, self.clock = enabled, clock

    def admit(self, principal, job_id, proposal_id, request_key):
        if self.enabled is not True:
            raise ValueError("Dedicated preparation executor is not registered")
        policy = self.policies.get(job_id)
        snapshot, proposal = approved_snapshot(
            self.records, principal, job_id, proposal_id, policy, self.clock())
        command = {"schema_version": 1, "job_id": job_id, "job_revision": snapshot.revision,
                   "requested_by": {"user_id": principal.user_id, "organization_id": principal.organization_id},
                   "proposal": proposal}
        # The operation store owns application-wide exclusion. Cross-record
        # admission is not atomic here; worker revalidation precedes all effects.
        return self.operations.admit(snapshot.record["application_id"], KIND, request_key, command)


def safe_target_receipt(receipt, plan, operation_id):
    if (not isinstance(receipt, dict) or receipt.get("operation_id") != operation_id
            or receipt.get("plan_id") != plan["plan_id"] or receipt.get("binding") != plan["target"]
            or receipt.get("status") != "available"
            or receipt.get("verified_scope") != "rds_ownership_network_tls"
            or receipt.get("encrypted") is not True or receipt.get("publicly_accessible") is not False
            or not isinstance(receipt.get("resource_id"), str)
            or not re.fullmatch(r"db-[A-Za-z0-9]{16,64}", receipt["resource_id"])):
        raise ValueError("Dedicated target evidence differs from the approved intent")
    return {key: receipt[key] for key in (
        "operation_id", "plan_id", "binding", "status", "verified_scope",
        "encrypted", "publicly_accessible", "resource_id")}


class PromotionPreparationWorker:
    def __init__(self, records, operations, policies, preparer, resolve_principal, *, owner, clock,
                 ownership=None, executor=None):
        if executor is not None and not isinstance(executor, EcsPreparationExecutor):
            raise TypeError("Trusted preparation executor identity required")
        self.records, self.operations, self.policies = records, operations, dict(policies)
        self.preparer, self.resolve_principal = preparer, resolve_principal
        self.owner, self.clock, self.ownership = owner, clock, ownership
        self.executor = executor

    def _validate(self, operation):
        command = operation.command
        if (not isinstance(command, dict)
                or set(command) != {"schema_version", "job_id", "job_revision", "requested_by", "proposal"}
                or type(command["schema_version"]) is not int or command["schema_version"] != 1):
            raise ValueError("Invalid dedicated preparation command")
        actor = command["requested_by"]
        if not isinstance(actor, dict) or set(actor) != {"user_id", "organization_id"}:
            raise ValueError("Invalid requester")
        principal = self.resolve_principal(actor["user_id"], actor["organization_id"])
        if (not isinstance(principal, Principal) or principal.user_id != actor["user_id"]
                or principal.organization_id != actor["organization_id"]):
            raise PermissionError("Requester membership changed")
        stored = command["proposal"]
        if not isinstance(stored, dict):
            raise TypeError("Missing approved proposal")
        snapshot, proposal = approved_snapshot(self.records, principal, command["job_id"],
            stored.get("proposal_id"), self.policies.get(command["job_id"]), self.clock())
        if (type(command["job_revision"]) is not int or snapshot.revision != command["job_revision"]
                or stored != proposal or operation.application_id != snapshot.record["application_id"]):
            raise RecordConflict("Deployment or approved proposal changed before preparation")
        # Consent by a different team member must still belong to a current deployer.
        approval = proposal["approval"]
        approver = self.resolve_principal(approval["user_id"], approval["organization_id"])
        if (not isinstance(approver, Principal) or approver.user_id != approval["user_id"]
                or approver.organization_id != approval["organization_id"]):
            raise PermissionError("Approver membership changed")
        OperatingReview(self.records).writer.snapshot(approver, command["job_id"])
        # Membership/state reads may have taken the quote past its deadline.
        require_current_cost_estimate(proposal, self.policies[command["job_id"]], self.clock())
        return proposal["plan"]

    def execute(self, operation_id, attempt_id):
        operation = self.operations.get(operation_id)
        if operation.kind != KIND:
            raise ValueError("Wrong worker kind")
        if operation.attempt_id != attempt_id:
            return {"status": "stale_attempt"}
        if operation.status in {"succeeded", "failed", "needs_attention"}:
            return {"status": operation.status}
        lease = self.operations.claim(operation_id, attempt_id, self.owner, seconds=900)
        if lease is None:
            return {"status": "not_claimed"}
        context = self.ownership(lease) if self.ownership else nullcontext(lambda: None)
        with context as guard:
            guard()
            try:
                plan = self._validate(operation)
            except (ValueError, TypeError, PermissionError, FileNotFoundError):
                if operation.external_pending or operation.external_intent is not None:
                    held = self.operations.require_attention(lease, {"stage": "revalidation_after_external_effect"})
                    return {"status": "needs_attention" if held else "lease_lost"}
                completed = self.operations.complete(lease, {"code": "promotion_revalidation_failed"},
                                                     succeeded=False)
                return {"status": "failed" if completed else "lease_lost"}
            except OSError:
                self.operations.interrupt(lease, {"stage": "source_read_unavailable"})
                return {"status": "interrupted"}
            # Recovery retains the original executor, never attributes an old
            # cloud request to the replacement worker's task or attempt.
            executor = (operation.external_intent or {}).get("executor")
            if operation.external_intent is None and self.executor is not None:
                executor = self.executor.record(self.owner, operation.attempt_id)
            intent = preparation_intent(plan, operation_id, executor)
            if operation.external_receipt is not None:
                if operation.external_intent != intent or operation.checkpoint != {"stage": "target_prepared"}:
                    held = self.operations.require_attention(lease, {"stage": "target_evidence_mismatch"})
                    return {"status": "needs_attention" if held else "lease_lost"}
                try:
                    receipt = operation.external_receipt
                    if isinstance(receipt, dict) and "observation" in receipt:
                        receipt = receipt["observation"]
                    safe = safe_target_receipt(receipt, plan, operation_id)
                except ValueError:
                    held = self.operations.require_attention(lease, {"stage": "target_evidence_mismatch"})
                    return {"status": "needs_attention" if held else "lease_lost"}
            else:
                if operation.external_pending or operation.external_intent is not None:
                    held = self.operations.require_attention(lease, {"stage": "target_outcome_uncertain"})
                    return {"status": "needs_attention" if held else "lease_lost"}
                guard()
                if not self.operations.begin_external(lease, intent):
                    return {"status": "lease_lost"}

                def preparation_guard():
                    # A long RDS wait must not retain an expired approval or
                    # stale membership. Never silently replace the pinned plan.
                    guard()
                    if self._validate(operation) != plan:
                        raise RecordConflict("Approved preparation plan changed")
                    guard()

                try:
                    receipt = self.preparer.prepare(plan, operation_id=operation_id, guard=preparation_guard)
                    preparation_guard()
                    safe = safe_target_receipt(receipt, plan, operation_id)
                except Exception:  # noqa: BLE001 -- uncertain external effects require reconciliation
                    self.operations.interrupt(lease, {"stage": "target_outcome_uncertain"})
                    return {"status": "needs_attention"}
                # An ambiguous commit must propagate, never invoke prepare again.
                if not self.operations.observe_external(lease, safe, {"stage": "target_prepared"}):
                    return {"status": "lease_lost"}
            guard()
            completed = self.operations.complete(lease, {
                "target_preparation": safe, "promotion_status": "not_started", "ready_to_cutover": False,
                "remaining_stages": ["snapshot", "copy", "catch_up", "verify", "cutover", "observe", "retire_source"]})
            return {"status": "succeeded" if completed else "lease_lost"}
