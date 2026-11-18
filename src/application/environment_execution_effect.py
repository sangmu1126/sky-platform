"""Fixed resource aggregation and bounded transfer effect for provider plugins."""

import hashlib
import json
import math
import re
from dataclasses import dataclass

from application.environment_admission import RegisteredEnvironmentExecution

_CHECK_REF = re.compile(r"ERC-[a-f0-9]{64}\Z")
_RUNTIME_REF = re.compile(r"ETR-[a-f0-9]{64}\Z")
_EVIDENCE_REF = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,127}\Z")
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_BASELINE_FIELDS = {
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
_RECEIPT_FIELDS = {
    "plan_id",
    "binding",
    "baseline",
    "single_writer",
    "source_retained",
    "availability_mode",
    "continuous_sync",
    "operation_elapsed_seconds",
    "write_pause_budget_seconds",
}


def _digest(prefix, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return prefix + hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class RegisteredEnvironmentResourceCheck:
    reference: str
    collect: object

    def __post_init__(self):
        if not isinstance(self.reference, str) or not _CHECK_REF.fullmatch(self.reference):
            raise ValueError("Digest-bound environment resource check required")
        if not callable(self.collect):
            raise TypeError("Environment resource collector required")
        owner = getattr(self.collect, "__self__", None)
        collector_reference = (
            getattr(owner, "reference", None)
            if owner is not None
            else getattr(self.collect, "reference", None)
        )
        if collector_reference != self.reference:
            raise ValueError("Environment resource collector differs from check reference")


class RegisteredEnvironmentTransferResources:
    def __init__(self, execution, checks):
        if not isinstance(execution, RegisteredEnvironmentExecution):
            raise TypeError("Registered environment execution required")
        if (
            not isinstance(checks, tuple)
            or not 1 <= len(checks) <= 32
            or not all(isinstance(value, RegisteredEnvironmentResourceCheck) for value in checks)
            or tuple(sorted(checks, key=lambda value: value.reference)) != checks
            or len({value.reference for value in checks}) != len(checks)
        ):
            raise ValueError("Canonical environment resource checks required")
        self.execution, self.checks = execution, checks
        self.reference = _digest(
            "EVR-",
            {
                "schema_version": 1,
                "profile": "registered_environment_transfer_resources_v1",
                "execution_revision": execution.revision,
                "checks": [value.reference for value in checks],
            },
        )

    def verify(self, execution, *, guard):
        if execution != self.execution or not callable(guard):
            raise ValueError("Exact guarded environment resource execution required")
        evidence = []
        for check in self.checks:
            guard()
            result = check.collect(execution, guard=guard)
            guard()
            if (
                not isinstance(result, dict)
                or set(result) != {"check_ref", "evidence_ref"}
                or result["check_ref"] != check.reference
                or not isinstance(result["evidence_ref"], str)
                or not _EVIDENCE_REF.fullmatch(result["evidence_ref"])
            ):
                raise ValueError("Exact registered environment resource evidence required")
            evidence.append(result["evidence_ref"])
        if len(set(evidence)) != len(evidence):
            raise ValueError("Distinct environment resource evidence required")
        return {
            "execution_revision": execution.revision,
            "verified": True,
            "evidence_refs": sorted(evidence),
        }


def _baseline(transfer, value, *, scopes):
    plan = transfer.document()
    fields = set(value) if isinstance(value, dict) else set()
    tables = value.get("tables") if isinstance(value, dict) else None
    sequences = value.get("sequences", []) if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or fields not in (_BASELINE_FIELDS, _BASELINE_FIELDS | {"sequences"})
        or any(value.get(key) != plan[key] for key in ("plan_id", "source", "target"))
        or not isinstance(value.get("schema_sha256"), str)
        or not _DIGEST.fullmatch(value["schema_sha256"])
        or not isinstance(tables, list)
        or not 1 <= len(tables) <= 100
        or any(
            not isinstance(item, dict)
            or set(item) != {"table", "rows", "sha256"}
            or not isinstance(item["table"], str)
            or not 1 <= len(item["table"].encode()) <= 63
            or type(item["rows"]) is not int
            or not 0 <= item["rows"] <= 100000
            or not isinstance(item["sha256"], str)
            or not _DIGEST.fullmatch(item["sha256"])
            for item in tables
        )
        or len({item["table"] for item in tables}) != len(tables)
        or sum(item["rows"] for item in tables) > 100000
        or not isinstance(sequences, list)
        or len(sequences) > 100
        or any(
            not isinstance(item, dict)
            or set(item) != {"table", "column", "next_value"}
            or any(
                not isinstance(item[name], str) or not 1 <= len(item[name].encode()) <= 63
                for name in ("table", "column")
            )
            or type(item["next_value"]) is not int
            or not 1 <= item["next_value"] < 2**63
            for item in sequences
        )
        or len({(item["table"], item["column"]) for item in sequences}) != len(sequences)
        or any(item["table"] not in {table["table"] for table in tables} for item in sequences)
        or value.get("verified_scope") not in scopes
        or value.get("source_retained") is not True
        or value.get("routing_changed") is not False
        or value.get("ready_to_cutover") is not False
        or value.get("requires_final_write_freeze") is not True
    ):
        raise ValueError("Exact registered environment transfer baseline required")
    return value


class RegisteredEnvironmentTransferEffect:
    def __init__(self, execution, runtime_ref, runtime):
        if not isinstance(execution, RegisteredEnvironmentExecution):
            raise TypeError("Registered environment execution required")
        if not isinstance(runtime_ref, str) or not _RUNTIME_REF.fullmatch(runtime_ref):
            raise ValueError("Digest-bound environment transfer runtime required")
        if not callable(runtime):
            raise TypeError("Registered environment transfer runtime required")
        if (
            getattr(runtime, "reference", None) != runtime_ref
            or getattr(runtime, "execution", None) != execution
        ):
            raise ValueError("Environment transfer runtime differs from registered reference")
        self.execution, self.runtime_ref, self.runtime = execution, runtime_ref, runtime
        self.reference = _digest(
            "EEF-",
            {
                "schema_version": 1,
                "profile": "registered_environment_transfer_effect_v1",
                "execution_revision": execution.revision,
                "transfer": execution.job.transfer.document(),
                "runtime_ref": runtime_ref,
            },
        )

    def __call__(self, execution, *, guard, journal):
        if (
            execution != self.execution
            or getattr(self.runtime, "reference", None) != self.runtime_ref
            or getattr(self.runtime, "execution", None) != execution
            or not callable(guard)
            or not callable(journal)
        ):
            raise ValueError("Exact guarded environment transfer effect required")
        transfer = execution.job.transfer
        guard()
        with self.runtime(execution, guard=guard, journal=journal) as resources:
            if (
                not isinstance(resources, tuple)
                or len(resources) != 2
                or getattr(resources[0], "transfer", None) != transfer
                or getattr(resources[1], "transfer", None) != transfer
            ):
                raise ValueError("Runtime differs from registered environment transfer")
            transport, flow = resources
            guard()
            verification = transport.verify_registration(transfer, guard=guard)
            if (
                not isinstance(verification, dict)
                or verification.get("plan_id") != transfer.document()["plan_id"]
                or verification.get("registration_verified") is not True
                or verification.get("mutation") is not False
            ):
                raise ValueError("Current transfer registration verification required")
            guard()
            journal({"stage": "initial_copy", "status": "intent"})
            baseline = _baseline(
                transfer,
                transport.copy(transfer, guard=guard),
                scopes={"locked_table_snapshot_copy"},
            )
            guard()
            journal({"stage": "initial_copy", "status": "observed"})
            result = flow.promote(transfer, baseline)
            final = _baseline(
                transfer,
                result.get("baseline") if isinstance(result, dict) else None,
                scopes={"final_locked_refresh"},
            )
            elapsed = result.get("operation_elapsed_seconds")
            if (
                set(result) != _RECEIPT_FIELDS
                or result.get("plan_id") != transfer.document()["plan_id"]
                or result.get("binding") != transfer.document()["target"]
                or final is not result["baseline"]
                or result.get("single_writer") is not True
                or result.get("source_retained") is not True
                or result.get("availability_mode") != "bounded_write_pause"
                or result.get("continuous_sync") is not False
                or result.get("write_pause_budget_seconds") != transfer.policy.write_pause_budget_seconds
                or type(elapsed) not in {int, float}
                or (type(elapsed) is float and not math.isfinite(elapsed))
                or not 0 <= elapsed <= transfer.policy.write_pause_budget_seconds
            ):
                raise ValueError("Exact bounded environment transfer receipt required")
            guard()
            return result
