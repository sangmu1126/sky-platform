"""Consume one reviewed environment admission under current durable authority.

The worker accepts only commands emitted by ``PostgresEnvironmentExecutionAdmission``.
It revalidates membership, review, G7 and registered resource ownership before
recording any external intent. Once an intent is durable, every exception is an
uncertain outcome that requires reconciliation rather than automatic replay.
"""

import re

from application.copy_guard import UncommittedCopyGuard
from application.database_cutover import OperationCutoverJournal
from application.environment_admission import (
    RegisteredEnvironmentExecution,
    validate_environment_execution_operation,
)
from domain.access import Action, Principal, permitted

KIND = "environment_transfer"
_EVIDENCE_REF = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,127}\Z")


def _resource_receipt(execution, receipt):
    if not isinstance(receipt, dict) or set(receipt) != {
        "execution_revision",
        "verified",
        "evidence_refs",
    }:
        raise ValueError("Exact registered resource ownership receipt required")
    references = receipt["evidence_refs"]
    if (
        receipt["execution_revision"] != execution.revision
        or receipt["verified"] is not True
        or not isinstance(references, list)
        or not 1 <= len(references) <= 32
        or references != sorted(set(references))
        or any(not isinstance(value, str) or not _EVIDENCE_REF.fullmatch(value) for value in references)
    ):
        raise ValueError("Verified registered resource ownership required")
    return {"evidence_refs": references}


class RegisteredEnvironmentExecutionWorker:
    def __init__(
        self,
        operations,
        admission,
        registrations,
        resolve_principal,
        resource_verifier,
        effect,
        *,
        owner,
        clock,
    ):
        self.operations = operations
        self.admission = admission
        self.registrations = dict(registrations)
        self.resolve_principal = resolve_principal
        self.resource_verifier = resource_verifier
        self.effect = effect
        self.owner = owner
        self.clock = clock
        if (
            any(
                not isinstance(value, RegisteredEnvironmentExecution) or key != value.job.id
                for key, value in self.registrations.items()
            )
            or not self.registrations
        ):
            raise ValueError("Trusted environment execution registrations required")
        if not all(
            callable(value)
            for value in (
                resolve_principal,
                getattr(admission, "revalidate", None),
                getattr(resource_verifier, "verify", None),
                effect,
                clock,
            )
        ):
            raise TypeError("Registered environment worker dependencies required")
        if not isinstance(owner, str) or not _EVIDENCE_REF.fullmatch(owner):
            raise ValueError("Registered environment worker owner required")

    def _current(self, command, execution):
        principal = self.resolve_principal(command["created_by"], command["organization_id"])
        if (
            not isinstance(principal, Principal)
            or principal.user_id != command["created_by"]
            or principal.organization_id != command["organization_id"]
            or not permitted(principal, Action.DEPLOY, execution.job.owner)
            or self.clock() >= execution.job.expires_at
        ):
            raise PermissionError("Current reviewed environment execution authority required")
        return principal

    def execute(self, operation_id, attempt_id):
        store = self.operations
        operation = store.get(operation_id)
        if (
            operation is None
            or operation.attempt_id != attempt_id
            or operation.kind != KIND
            or operation.status != "queued"
            or operation.external_pending
        ):
            return {"status": "not_claimed"}
        if not isinstance(operation.command, dict):
            raise TypeError("Persisted reviewed environment command is invalid")
        execution = self.registrations.get(operation.command.get("registration_id"))
        if execution is None:
            raise ValueError("Registered environment execution is unavailable")
        command = validate_environment_execution_operation(operation, execution)
        principal = self._current(command, execution)
        self.admission.revalidate(principal, execution, operation)
        lease = store.claim(operation.id, operation.attempt_id, self.owner, seconds=900)
        if lease is None:
            return {"status": "not_claimed"}
        journal = OperationCutoverJournal(store, lease, effect_kind=KIND)

        def check():
            journal.guard()
            current = self._current(command, execution)
            self.admission.revalidate(current, execution, store.get(operation.id))

        guard = UncommittedCopyGuard(check)
        begun = False
        try:
            guard()
            receipt = _resource_receipt(
                execution,
                self.resource_verifier.verify(execution, guard=guard),
            )
            guard()
            journal(
                {
                    "stage": "resource_ownership",
                    "status": "observed",
                    "receipt": receipt,
                }
            )
            begun = True
            journal.begin(
                {
                    "execution_revision": execution.revision,
                    "transfer": execution.job.transfer.document(),
                    "review_id": command["review_id"],
                    "gate_record_id": command["gate_record_id"],
                }
            )
            result = self.effect(execution, guard=guard, journal=journal)
            if not isinstance(result, dict) or not result:
                raise ValueError("Registered environment effect receipt required")
            guard()
            journal.finish(result)
            return {"status": "succeeded"}
        except Exception:  # noqa: BLE001 -- post-intent outcomes are never replayed automatically
            guard.halted.set()
            if begun:
                journal.hold()
                return {"status": "needs_attention"}
            store.complete(
                lease,
                {"code": "environment_execution_precondition_failed"},
                succeeded=False,
            )
            return {"status": "failed"}
