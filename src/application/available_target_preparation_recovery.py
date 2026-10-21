"""Narrow recovery authority for stopped, audited create-only ECS executors.

An available owned target with deletion protection is rechecked on every guard.
The registered code can only issue CreateDBInstance for this identifier; that API
cannot overwrite an existing instance. This does not cancel provider requests or
protect against a compromised administrator deleting/replacing resources between
reads. No runtime enables this authority by default.
"""

import hashlib
import json
import time
from contextlib import contextmanager

from application.database_promotion_workflow import preparation_intent, safe_target_receipt
from ports.preparation_executor import CreateOnlyPreparationProfile
from ports.preparation_recovery import AvailableTargetRecoveryEvidence, PreparationRecoveryFence
from ports.state import RecordConflict


class AvailableTargetPreparationRecoveryAuthority:
    def __init__(self, operations, stopped_observer, target_observer, *, monotonic=time.monotonic, lifetime=120):
        if (not isinstance(stopped_observer.profile, CreateOnlyPreparationProfile)
                or stopped_observer.workspace != operations.workspace
                or type(lifetime) is not int or not 1 <= lifetime <= 300):
            raise ValueError("Registered create-only executor profile and bounded recovery lifetime required")
        self.operations, self.stopped, self.target = operations, stopped_observer, target_observer
        self.profile = stopped_observer.profile
        self.monotonic, self.lifetime = monotonic, lifetime

    @contextmanager
    def hold(self, operation):
        started, active = self.monotonic(), True

        def current():
            if not active or self.monotonic() - started >= self.lifetime:
                raise OSError("Recovery exclusion observation expired")
            if self.stopped.profile != self.profile:
                raise RecordConflict("Registered executor profile changed during recovery")
            if self.operations.get(operation.id) != operation:
                raise RecordConflict("Original blocked operation changed")

        try:
            current()
            plan = operation.command["proposal"]["plan"]
            intent = preparation_intent(plan, operation.id, (operation.external_intent or {}).get("executor"))
            if intent != operation.external_intent or "executor" not in intent:
                raise ValueError("Pinned original execution intent required")
            stopped = self.stopped.observe(operation, guard=current)
            if (stopped.get("workspace") != self.operations.workspace
                    or stopped.get("operation_id") != operation.id
                    or stopped.get("attempt_id") != operation.attempt_id
                    or stopped.get("operation_version") != operation.row_version
                    or stopped.get("executor") != intent["executor"]
                    or stopped.get("execution_profile") != self.profile.record()
                    or stopped.get("scope") != "ecs_executor_stopped_only"):
                raise ValueError("Stopped executor evidence scope mismatch")
            initial = safe_target_receipt(
                self.target.observe(plan, operation_id=operation.id, guard=current), plan, operation.id)
            evidence = AvailableTargetRecoveryEvidence(
                self.profile, stopped["evidence_ref"], stopped["stopped_at"], initial["resource_id"])
            document = {"workspace": self.operations.workspace, "operation_id": operation.id,
                        "attempt_id": operation.attempt_id, "row_version": operation.row_version,
                        "evidence": evidence.record()}
            digest = hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

            def check():
                current()
                observed = safe_target_receipt(
                    self.target.observe(plan, operation_id=operation.id, guard=current), plan, operation.id)
                if observed != initial:
                    raise ValueError("Prepared target identity changed during recovery")
                current()

            check()
            yield PreparationRecoveryFence(
                self.operations.workspace, operation.id, operation.attempt_id, operation.row_version,
                "evidence:available-target-recovery/" + digest, check, evidence)
        finally:
            active = False
