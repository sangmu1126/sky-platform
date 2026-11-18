"""Explicit provider-neutral write-pause flow using qualified transport ports.

Operator/worker admission must supply exclusive execution, durable intent and
current authorization. DBM metadata review is not such an admission. Legacy DBP
entrypoints retain their constraints and never receive fabricated AWS bindings.
"""

import time
from dataclasses import asdict

from application.database_cutover import DatabaseCutover
from domain.database_transfer import RegisteredDatabaseTransfer


class _RegisteredSync:
    def __init__(self, transport, transfer):
        self.transport, self.transfer = transport, transfer

    def refresh(self, plan, **kwargs):
        if plan != self.transfer.document():
            raise ValueError("Cutover transfer registration changed")
        return self.transport.refresh(self.transfer, **kwargs)


class _BoundedCopyGuard:
    def __init__(self, flow):
        self.flow = flow

    def __call__(self):
        self.flow._guard_budget()

    def uncommitted_copy_checkpoint(self):
        flow = self.flow
        if flow._deadline is not None and flow._clock() >= flow._deadline:
            raise RuntimeError("Environment write-pause budget exceeded; reconcile before further effects")
        getattr(flow._external_guard, "uncommitted_copy_checkpoint", flow._external_guard)()
        if flow._deadline is not None and flow._clock() >= flow._deadline:
            raise RuntimeError("Environment write-pause budget exceeded; reconcile before further effects")


class EnvironmentDatabaseCutover(DatabaseCutover):
    def __init__(
        self,
        transfer,
        transport,
        source_fence,
        target_fence,
        traffic,
        *,
        guard,
        journal,
        clock=time.monotonic,
    ):
        if (
            not isinstance(transfer, RegisteredDatabaseTransfer)
            or getattr(transport, "transfer", None) != transfer
        ):
            raise ValueError("Matching registered environment transport required")
        self.transfer = transfer
        self._external_guard, self._clock, self._deadline = guard, clock, None
        if (
            source_fence.binding != transfer.source
            or target_fence.binding != transfer.target
            or traffic.bindings != [asdict(transfer.source), asdict(transfer.target)]
        ):
            raise ValueError("Registered cutover endpoints differ")
        super().__init__(
            _RegisteredSync(transport, transfer),
            source_fence,
            target_fence,
            traffic,
            guard=_BoundedCopyGuard(self),
            journal=journal,
            preserve_reads=True,
        )

    def _guard_budget(self):
        self._external_guard()
        if self._deadline is not None and self._clock() >= self._deadline:
            raise RuntimeError("Environment write-pause budget exceeded; reconcile before further effects")

    def _run_bounded(self, action, transfer, baseline):
        if transfer != self.transfer or self._deadline is not None:
            raise ValueError("Exact serial environment cutover registration required")
        started = self._clock()
        self._deadline = started + self.transfer.policy.write_pause_budget_seconds
        try:
            result = action(transfer.document(), baseline)
            return {
                **result,
                "availability_mode": "bounded_write_pause",
                "continuous_sync": False,
                "operation_elapsed_seconds": self._clock() - started,
                "write_pause_budget_seconds": self.transfer.policy.write_pause_budget_seconds,
            }
        finally:
            self._deadline = None

    def _validate(self, plan, baseline):
        if (
            plan != self.transfer.document()
            or not isinstance(baseline, dict)
            or any(baseline.get(key) != plan[key] for key in ("plan_id", "source", "target"))
            or baseline.get("verified_scope") not in {"locked_table_snapshot_copy", "final_locked_refresh"}
            or baseline.get("source_retained") is not True
            or baseline.get("routing_changed") is not False
            or baseline.get("ready_to_cutover") is not False
            or baseline.get("requires_final_write_freeze") is not True
        ):
            raise ValueError("Exact registered environment copy baseline required")

    def promote(self, transfer, baseline):
        return self._run_bounded(super().promote, transfer, baseline)

    def rollback(self, transfer, final_baseline):
        return self._run_bounded(super().rollback, transfer, final_baseline)
