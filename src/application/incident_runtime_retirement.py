"""One-shot retirement of the held runtime, with explicit uncertain-outcome inspection."""

from copy import deepcopy
from uuid import uuid4

from application.incident_runtime_inspection import IncidentRuntimeInspection
from ports.state import RecordConflict

FIELD = "security_runtime_retirement"


class IncidentRuntimeRetirement:
    def __init__(self, records, execution, runtime, *, clock, revalidate):
        self.scope = IncidentRuntimeInspection(records, None, clock=clock, revalidate=revalidate)
        self.writer, self.execution, self.runtime = self.scope.writer, execution, runtime
        self.clock = clock

    def _scope(self, principal, job_id, options):
        from application.security_hold import validate_release_request

        now = self.clock()
        validate_release_request(
            options["incident_id"],
            "runtime-retirement",
            options["expected_revision"],
            options["expected_boundary"],
            now,
        )
        snapshot = self.scope._scope(
            principal, job_id, options["incident_id"], options["expected_boundary"], now
        )
        if snapshot.revision != options["expected_revision"]:
            raise RecordConflict("Incident changed since retirement review")
        receipt = self.execution.inspect(principal, job_id, **options)
        if (
            receipt.get("sky_worker_external_intents_fenced") is not True
            or receipt.get("registered_operation_requests_settled") is not True
            or receipt.get("pending_inventory_complete") is not True
            or receipt.get("pending_operation_ids") != []
        ):
            raise ValueError("Fenced Sky operations with no unresolved external requests required")
        return snapshot

    def retire(self, principal, job_id, **options):
        snapshot = self._scope(principal, job_id, options)
        if snapshot.record.get(FIELD) is not None:
            raise ValueError("Existing retirement requires explicit inspection, never automatic replay")

        def unchanged():
            if self._scope(principal, job_id, options) != snapshot:
                raise RecordConflict("Runtime changed during retirement preflight")

        target = self.runtime.preflight(deepcopy(snapshot.record["result"]), guard=unchanged)
        unchanged()
        intent = {
            "schema_version": 1,
            "operation_id": uuid4().hex,
            "incident_id": options["incident_id"],
            "boundary_id": options["expected_boundary"],
            "requested_by": principal.user_id,
            "requested_at": self.clock(),
            "target": target,
            "phase": "applying",
        }
        self.writer.patch(
            principal, job_id, snapshot.revision, {FIELD: intent, "promotion_automation_consent": None}
        )

        def guard():
            current_options = {**options, "expected_revision": snapshot.revision + 1}
            current = self._scope(principal, job_id, current_options)
            if current.record != {**snapshot.record, FIELD: intent, "promotion_automation_consent": None}:
                raise RecordConflict("Runtime retirement execution ownership changed")
            return current

        try:
            receipt = self.runtime.retire(deepcopy(snapshot.record["result"]), deepcopy(target), guard=guard)
            current = guard()
            validate_receipt(receipt, snapshot.record["result"])
            completed = {**intent, "phase": "retired", "observed_at": self.clock(), "receipt": receipt}
            self.writer.patch(principal, job_id, current.revision, {FIELD: completed})
            return deepcopy(completed)
        except Exception:  # noqa: BLE001 -- preserve uncertainty without exposing native diagnostics
            try:
                current = guard()
                self.writer.patch(
                    principal, job_id, current.revision, {FIELD: {**intent, "phase": "needs_attention"}}
                )
            except Exception:  # noqa: BLE001,S110 -- leave the original intent if storage is unavailable
                pass
            raise OSError(
                "Retirement outcome requires inspection; never replay deletion automatically"
            ) from None

    def inspect(self, principal, job_id, *, confirm=False, **options):
        snapshot = self._scope(principal, job_id, options)
        record = snapshot.record.get(FIELD)
        if (
            not isinstance(record, dict)
            or record.get("phase") not in {"applying", "needs_attention", "retired"}
            or (record.get("incident_id"), record.get("boundary_id"))
            != (options["incident_id"], options["expected_boundary"])
            or record.get("target", {}).get("runtime") != snapshot.record.get("result")
        ):
            raise ValueError("Exact persisted retirement intent required")
        if confirm and record["phase"] == "applying":
            raise ValueError("An active retirement executor must finish or record uncertainty first")

        def guard():
            if self._scope(principal, job_id, options) != snapshot:
                raise RecordConflict("Incident changed during retirement inspection")

        receipt = self.runtime.inspect_retired(
            deepcopy(snapshot.record["result"]), deepcopy(record["target"]), guard=guard
        )
        validate_receipt(receipt, snapshot.record["result"])
        guard()
        changed = confirm and record["phase"] == "needs_attention"
        if changed:
            self.writer.patch(
                principal,
                job_id,
                snapshot.revision,
                {FIELD: {**record, "phase": "retired", "observed_at": self.clock(), "receipt": receipt}},
            )
        return {
            "metadata_revision": snapshot.revision + int(changed),
            "operation_id": record["operation_id"],
            "registered_runtime_retirement_verified": True,
            "state_changed": changed,
            "read_only": not confirm,
            "execution_scope": "registered_sky_operations_and_ecs_service",
            "arbitrary_aws_launchers_fenced": False,
            "recovery_authorized": False,
        }


def validate_receipt(value, runtime):
    from domain.incident_runtime import runtime_identity

    _, _, _, service, definition, *_ = runtime_identity(runtime)
    if (
        not isinstance(value, dict)
        or value.get("service_arn") != service
        or value.get("task_definition_arn") != definition
        or value.get("read_only") is not True
        or value.get("registered_service_retired") is not True
        or value.get("registered_task_definition_inactive") is not True
        or value.get("registered_tasks_stopped") is not True
        or value.get("scope") != "registered_ecs_service_and_task_definition"
        or value.get("arbitrary_aws_launchers_fenced") is not False
        or value.get("recovery_authorized") is not False
    ):
        raise ValueError("Exact limited runtime retirement evidence required")
