"""Explicit approved cutover admission/execution for trusted registrations.

No public route or default hosted runtime enables this workflow. Registrations
and flow factories are operator-owned, never taken from an uploaded application
or a queue message. Preparation and cutover have separate operation kinds.
"""

import hashlib
import json
import re
from contextlib import nullcontext
from copy import deepcopy
from dataclasses import replace
from datetime import datetime

from application.database_cutover import OperationCutoverJournal
from application.database_promotion_workflow import PromotionPreparationWorker, approved_snapshot
from application.deployment_writes import DeploymentMetadataWriter
from ports.state import RecordConflict

KIND = "db_dedicated_cutover"
_EVIDENCE = {"target_ownership_tls", "schema_copy", "all_writers_controlled", "control_auth_tls"}
_BASELINE = {
    "plan_id",
    "source",
    "target",
    "schema_sha256",
    "tables",
    "verified_scope",
    "source_retained",
    "routing_changed",
    "ready_to_cutover",
    "requires_final_write_freeze",
}


def execution_registration(registration, plan, now):
    """Pin bounded, credential-free evidence before creating any external intent."""
    if (
        not isinstance(registration, dict)
        or set(registration)
        != {
            "plan_id",
            "source",
            "target",
            "baseline",
            "controller_id",
            "controller_revision",
            "verified_until",
            "evidence",
        }
        or any(registration[key] != plan[key] for key in ("plan_id", "source", "target"))
        or not isinstance(registration["controller_id"], str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", registration["controller_id"])
        or not isinstance(registration["controller_revision"], str)
        or not re.fullmatch(r"[a-f0-9]{64}", registration["controller_revision"])
        or not isinstance(registration["evidence"], dict)
        or set(registration["evidence"]) != _EVIDENCE
        or any(
            not isinstance(ref, str) or not re.fullmatch(r"evidence:[A-Za-z0-9/_-]{1,200}", ref)
            for ref in registration["evidence"].values()
        )
    ):
        raise ValueError("Verified cutover registration required")
    expires, current = datetime.fromisoformat(registration["verified_until"]), datetime.fromisoformat(now)
    if expires.tzinfo is None or current.tzinfo is None or expires <= current:
        raise ValueError("Cutover registration expired")
    baseline = registration["baseline"]
    if (
        not isinstance(baseline, dict)
        or not _BASELINE <= set(baseline) <= _BASELINE | {"sequences", "source_snapshot_plan_id"}
        or any(baseline[key] != plan[key] for key in ("plan_id", "source", "target"))
        or baseline["verified_scope"]
        not in {"locked_table_snapshot_copy", "revalidated_destination_snapshot"}
        or baseline["source_retained"] is not True
        or baseline["routing_changed"] is not False
        or baseline["ready_to_cutover"] is not False
        or baseline["requires_final_write_freeze"] is not True
        or not isinstance(baseline["schema_sha256"], str)
        or not re.fullmatch(r"[a-f0-9]{64}", baseline["schema_sha256"])
        or not isinstance(baseline["tables"], list)
        or not 1 <= len(baseline["tables"]) <= 100
    ):
        raise ValueError("Verified initial copy baseline required")
    names = set()
    original_plan = baseline.get("source_snapshot_plan_id")
    if (baseline["verified_scope"] == "revalidated_destination_snapshot" and original_plan is None) or (
        original_plan is not None
        and (not isinstance(original_plan, str) or not re.fullmatch(r"DBP-[a-f0-9]{16}", original_plan))
    ):
        raise ValueError("Original copy plan identity required for a revalidated baseline")
    for table in baseline["tables"]:
        if (
            not isinstance(table, dict)
            or set(table) != {"table", "rows", "sha256"}
            or not isinstance(table["table"], str)
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", table["table"])
            or table["table"] in names
            or type(table["rows"]) is not int
            or not 0 <= table["rows"] <= 100000
            or not isinstance(table["sha256"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", table["sha256"])
        ):
            raise ValueError("Invalid copy table evidence")
        names.add(table["table"])
    sequences = baseline.get("sequences", [])
    if not isinstance(sequences, list) or len(sequences) > 100:
        raise ValueError("Bounded identity sequence baseline required")
    sequence_keys = set()
    for sequence in sequences:
        if (
            not isinstance(sequence, dict)
            or set(sequence) != {"table", "column", "next_value"}
            or sequence.get("table") not in names
            or not isinstance(sequence.get("column"), str)
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", sequence["column"])
            or type(sequence.get("next_value")) is not int
            or not 1 <= sequence["next_value"] < 2**63
            or (sequence["table"], sequence["column"]) in sequence_keys
        ):
            raise ValueError("Invalid identity sequence baseline")
        sequence_keys.add((sequence["table"], sequence["column"]))
    encoded = json.dumps(registration, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(encoded) > 65536:
        raise ValueError("Cutover registration too large")
    return hashlib.sha256(encoded).hexdigest()


class PromotionCutoverAdmission:
    def __init__(self, records, operations, policies, registrations, *, clock, enabled=False):
        self.records, self.operations = records, operations
        self.policies, self.registrations = policies, registrations
        self.clock, self.enabled = clock, enabled

    def admit(self, principal, job_id, proposal_id, request_key):
        if self.enabled is not True:
            raise ValueError("Cutover executor and transport are not registered")
        now = self.clock()
        snapshot, proposal = approved_snapshot(
            self.records, principal, job_id, proposal_id, self.policies.get(job_id), now
        )
        digest = execution_registration(self.registrations.get(job_id), proposal["plan"], now)
        approval = {
            "schema_version": 1,
            "job_id": job_id,
            "job_revision": snapshot.revision,
            "requested_by": {"user_id": principal.user_id, "organization_id": principal.organization_id},
            "proposal": proposal,
        }
        return self.operations.admit(
            snapshot.record["application_id"],
            KIND,
            request_key,
            {"schema_version": 1, "approval": approval, "registration_digest": digest},
        )


class PromotionCutoverWorker:
    def __init__(
        self,
        records,
        operations,
        policies,
        registrations,
        flow_factory,
        resolve_principal,
        *,
        owner,
        clock,
        ownership=None,
        performance_observer=None,
    ):
        from ports.promotion_performance import PromotionPerformanceObserver

        if performance_observer is not None and not isinstance(
            performance_observer, PromotionPerformanceObserver
        ):
            raise TypeError("Trusted promotion performance observer required")
        self.performance_observer = performance_observer
        self.records, self.operations, self.registrations = records, operations, registrations
        self.flow_factory, self.owner, self.clock, self.ownership = flow_factory, owner, clock, ownership
        self.validator = PromotionPreparationWorker(
            records, operations, policies, None, resolve_principal, owner=owner, clock=clock
        )

    def _validate(self, operation):
        command = operation.command
        if (
            not isinstance(command, dict)
            or set(command) != {"schema_version", "approval", "registration_digest"}
            or type(command["schema_version"]) is not int
            or command["schema_version"] != 1
        ):
            raise ValueError("Invalid cutover command")
        plan = self.validator._validate(replace(operation, command=command["approval"]))
        job_id = command["approval"]["job_id"]
        registration = deepcopy(self.registrations.get(job_id))
        if execution_registration(registration, plan, self.clock()) != command["registration_digest"]:
            raise ValueError("Cutover controller or evidence changed")
        return plan, registration

    def execute(self, operation_id, attempt_id):
        operation = self.operations.get(operation_id)
        if operation.kind != KIND:
            raise ValueError("Wrong cutover worker kind")
        if operation.attempt_id != attempt_id:
            return {"status": "stale_attempt"}
        if operation.status in {"succeeded", "failed", "needs_attention"}:
            return {"status": operation.status}
        lease = self.operations.claim(operation_id, attempt_id, self.owner, seconds=900)
        if lease is None:
            return {"status": "not_claimed"}
        journal = OperationCutoverJournal(self.operations, lease)
        context = self.ownership(lease) if self.ownership else nullcontext(lambda: None)
        with context as ownership_guard:
            if operation.external_pending or operation.external_intent is not None:
                journal.hold()
                return {"status": "needs_attention"}
            try:
                ownership_guard()
                plan, registration = self._validate(operation)
            except (ValueError, TypeError, KeyError, PermissionError, FileNotFoundError):
                saved = self.operations.complete(
                    lease, {"code": "cutover_revalidation_failed"}, succeeded=False
                )
                return {"status": "failed" if saved else "lease_lost"}
            except OSError:
                self.operations.interrupt(lease, {"stage": "cutover_source_unavailable"})
                return {"status": "interrupted"}
            approval = operation.command["approval"]
            actor = approval["requested_by"]
            principal = self.validator.resolve_principal(actor["user_id"], actor["organization_id"])
            revision = approval["job_revision"]
            metadata_written = False

            def guard():
                ownership_guard()
                journal.guard()
                current = self.validator.resolve_principal(actor["user_id"], actor["organization_id"])
                snapshot = DeploymentMetadataWriter(self.records).snapshot(current, approval["job_id"])
                if snapshot.revision != revision:
                    raise RecordConflict("Deployment changed during cutover")
                if not metadata_written:
                    self._validate(operation)

            try:
                guard()
                # Factory construction must be pure. All effectful adapter calls
                # occur only after the durable external intent below.
                flow = self.flow_factory(plan, registration, guard=guard, journal=journal)
                journal.begin(plan)
                before = None
                if self.performance_observer is not None:
                    try:
                        from application.promotion_performance import validate_window

                        before = self.performance_observer.measure(plan, plan["source"], guard=guard)
                        validate_window(before)
                    except Exception:  # noqa: BLE001 -- optional telemetry cannot invent a benefit
                        guard()  # Execution/approval loss must still abort before cutover.
                        before = None
                guard()
                receipt = flow.promote(plan, registration["baseline"])
                performance = None
                if self.performance_observer is not None:
                    performance = {
                        "status": "unverified",
                        "reason": "collection_unavailable",
                        "automatic_action": False,
                    }
                    if before is not None:
                        try:
                            from application.promotion_performance import compare_windows

                            after = self.performance_observer.measure(plan, plan["target"], guard=guard)
                            performance = compare_windows(
                                before,
                                after,
                                source=plan["source"],
                                target=plan["target"],
                                source_revision=plan["source_revision"],
                                image_digest=before["image_digest"],
                                now=self.clock(),
                            )
                            expected_image = receipt.get("active_runtime", {}).get("image_digest")
                            if (
                                before["image_digest"] is not None
                                and before["image_digest"] != expected_image
                            ):
                                raise ValueError("Measured image differs from the published runtime")
                        except Exception:  # noqa: BLE001 -- preserve successful cutover, report missing evidence
                            guard()
                            performance = {
                                "status": "unverified",
                                "reason": "incomparable_or_unavailable",
                                "automatic_action": False,
                            }
                    guard()
                if (
                    not isinstance(receipt, dict)
                    or set(receipt)
                    not in (
                        {"plan_id", "binding", "baseline", "single_writer", "source_retained"},
                        {
                            "plan_id",
                            "binding",
                            "baseline",
                            "single_writer",
                            "source_retained",
                            "active_runtime",
                        },
                    )
                    or receipt["plan_id"] != plan["plan_id"]
                    or receipt["binding"] != plan["target"]
                    or receipt["single_writer"] is not True
                    or receipt["source_retained"] is not True
                ):
                    raise ValueError("Invalid cutover result")
                # Validate the final baseline's shape too; retain its real scope.
                checked = deepcopy(registration)
                checked["baseline"] = {**receipt["baseline"], "verified_scope": "locked_table_snapshot_copy"}
                if receipt["baseline"].get("verified_scope") != "final_locked_refresh":
                    raise ValueError("Final synchronization evidence required")
                execution_registration(checked, plan, self.clock())
                guard()
                snapshot = DeploymentMetadataWriter(self.records).snapshot(principal, approval["job_id"])
                active = receipt.get("active_runtime")
                if active is not None and (
                    not isinstance(active, dict)
                    or active.get("database", {}).get("binding") != plan["target"]
                    or active.get("image_digest") != snapshot.record["result"].get("image_digest")
                    or active.get("image_identity", {}).get("status") != "passed"
                    or any(
                        active.get("verification", {}).get(key) != "verified"
                        for key in ("http", "image", "database_authentication", "stable_route")
                    )
                    or active.get("traffic_strategy") != "blue_green"
                ):
                    raise ValueError("Published runtime must verify the same image and target database")
                projection = {
                    "operation_id": operation_id,
                    "registration_digest": operation.command["registration_digest"],
                    "controller_id": registration["controller_id"],
                    **receipt,
                }
                changes = {
                    "workload_database_binding": plan["target"],
                    "database_promotion": projection,
                    "result": {
                        **(active if active is not None else snapshot.record["result"]),
                        "database_promotion": projection,
                    },
                    "promotion_automation_consent": None,
                }
                if performance is not None:
                    from application.operating_review import deployment_observation_binding

                    changes["promotion_performance_review"] = {
                        **performance,
                        "operation_id": operation_id,
                        "reviewed_at": self.clock(),
                        "deployment_binding": deployment_observation_binding({**snapshot.record, **changes}),
                    }
                saved = DeploymentMetadataWriter(self.records).patch(
                    principal,
                    approval["job_id"],
                    revision,
                    changes,
                )
                revision, metadata_written = saved.revision, True
                # Metadata and operation are separate transactions. Failure here
                # retains the scope for reconciliation, never reruns app cutover.
                journal.finish(projection)
                return {"status": "succeeded"}
            except Exception:  # noqa: BLE001 -- uncertain writes require durable reconciliation
                journal.hold()
                return {"status": "needs_attention"}
