"""Bounded investigation/proposal tools. No production mutation or free commands.

Handlers are operator registrations. Their sandbox/inspection implementations are
separate ports; naming a tool never implements that capability. Model arguments
cannot choose an actor, account, DB, URL, command or unregistered artifact.
"""

import json
import re
import time
from dataclasses import dataclass
from threading import Event, RLock
from types import MappingProxyType

from domain.access import Principal
from domain.environment_transition import TransitionScope

TOOL_FIELDS = {
    "get_system_inventory": {},
    "get_environment_capabilities": {"environment_ref": "environment"},
    "request_inspection": {"criterion_ref": "criterion"},
    "read_evidence": {"evidence_ref": "evidence"},
    "propose_change": {
        "source_revision": "revision",
        "evidence_refs": "evidence_list",
        "change_ref": "change",
    },
    "request_rehearsal": {"proposal_ref": "proposal"},
    "get_rehearsal_result": {"rehearsal_ref": "rehearsal"},
    "submit_transition_plan": {"proposal_ref": "proposal", "evidence_refs": "evidence_list"},
}
FACT_CODES = frozenset(
    {
        "http_container",
        "postgresql",
        "sqlite",
        "arm64",
        "amd64",
        "source_verified",
        "target_unverified",
        "gate_blocked",
        "writes_require_pause",
        "stateful_process",
        "no_session_state",
        "cost_unverified",
        "data_copy_required",
        "tls_required",
        "proposal_only",
        "rehearsal_pending",
        "unsupported_resource",
        "missing_evidence",
    }
)


@dataclass(frozen=True)
class InvestigationReceipt:
    status: str
    fact_codes: tuple[str, ...]
    artifact_refs: tuple[str, ...] = ()

    def __post_init__(self):
        if (
            self.status not in {"metadata", "blocked", "proposal_only", "rehearsal_pending", "review_only"}
            or not isinstance(self.fact_codes, tuple)
            or len(self.fact_codes) > 32
            or any(v not in FACT_CODES for v in self.fact_codes)
            or not isinstance(self.artifact_refs, tuple)
            or len(self.artifact_refs) > 16
            or any(
                not isinstance(v, str)
                or not re.fullmatch(r"(?:evidence|proposal|rehearsal|review)-[a-f0-9]{64}", v)
                for v in self.artifact_refs
            )
        ):
            raise ValueError("Bounded public investigation receipt required")


class InvestigationTools:
    def __init__(
        self,
        principal,
        scope,
        handlers,
        references,
        *,
        current_principal,
        authorizer,
        verify_artifact,
        max_calls=24,
        budget_seconds=60,
        clock=time.monotonic,
    ):
        if (
            not isinstance(principal, Principal)
            or not isinstance(scope, TransitionScope)
            or principal.organization_id != scope.organization_id
        ):
            raise PermissionError("Owned investigation scope required")
        if (
            not isinstance(handlers, dict)
            or set(handlers) - set(TOOL_FIELDS)
            or any(not callable(v) for v in handlers.values())
        ):
            raise ValueError("Only registered investigation tool handlers are allowed")
        if (
            type(max_calls) is not int
            or not 1 <= max_calls <= 24
            or type(budget_seconds) is not int
            or not 1 <= budget_seconds <= 60
            or set(references) - {"environment", "criterion", "evidence", "change", "proposal", "rehearsal"}
        ):
            raise ValueError("Bounded investigation policy required")
        self.principal, self.scope = principal, scope
        self.handlers = MappingProxyType(dict(handlers))
        self.references = {k: set(v) for k, v in references.items()}
        if any(
            not isinstance(v, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}", v)
            for values in self.references.values()
            for v in values
        ):
            raise ValueError("Opaque registered references required")
        self.current_principal, self.authorizer = current_principal, authorizer
        if not callable(verify_artifact):
            raise TypeError("Current artifact ownership verifier required")
        self.verify_artifact = verify_artifact
        self.max_calls, self.clock, self.deadline = max_calls, clock, clock() + budget_seconds
        self.calls, self.lock, self.halted = 0, RLock(), Event()

    def _authorize(self):
        if self.halted.is_set():
            raise RuntimeError("Investigation outcome requires reconciliation")
        if self.clock() >= self.deadline:
            raise TimeoutError("Investigation deadline expired")
        if self.current_principal(self.principal) != self.principal:
            raise PermissionError("Investigation membership changed")
        self.authorizer.authorize(self.principal, self.scope.application_id)

    def halt(self):
        self.halted.set()

    def _claim_call(self):
        self.calls += 1
        if self.calls > self.max_calls:
            raise ValueError("Investigation tool budget exhausted")
        self._authorize()

    def invoke(self, name, arguments):
        with self.lock:
            self._claim_call()
            return self._invoke_registered(name, arguments)

    def invoke_json(self, name, raw):
        with self.lock:
            self._claim_call()
            if not isinstance(raw, str) or len(raw.encode()) > 4096:
                raise ValueError("Bounded JSON required")

            def unique(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("Duplicate tool argument")
                    result[key] = value
                return result

            return self._invoke_registered(name, json.loads(raw, object_pairs_hook=unique))

    def _invoke_registered(self, name, arguments):
        if (
            name not in TOOL_FIELDS
            or not isinstance(arguments, dict)
            or set(arguments) != set(TOOL_FIELDS[name])
        ):
            raise ValueError("Unregistered tool or extra arguments")
        raw = json.dumps(arguments, allow_nan=False)
        if len(raw.encode()) > 4096:
            raise ValueError("Bounded tool arguments required")
        for key, kind in TOOL_FIELDS[name].items():
            value = arguments[key]
            if kind == "revision":
                if value != self.scope.source_revision:
                    raise ValueError("Source revision changed")
            elif kind == "evidence_list":
                if (
                    not isinstance(value, list)
                    or not 1 <= len(value) <= 16
                    or any(not isinstance(v, str) for v in value)
                    or len(set(value)) != len(value)
                    or any(v not in self.references.get("evidence", ()) for v in value)
                ):
                    raise ValueError("Only registered evidence references allowed")
            elif not isinstance(value, str) or value not in self.references.get(kind, ()):
                raise ValueError("Unregistered resource reference")
        handler = self.handlers.get(name)
        if handler is None:
            return InvestigationReceipt("blocked", ("unsupported_resource",))
        try:
            result = handler(self.principal, self.scope, json.loads(raw))
            self._authorize()
        except Exception:  # noqa: BLE001 -- never return credentials or handler diagnostics to a model
            self.halt()
            raise RuntimeError("Registered investigation tool blocked") from None
        if not isinstance(result, InvestigationReceipt):
            self.halt()
            raise TypeError("Typed public receipt required")
        if name in {"propose_change", "submit_transition_plan"} and result.status not in {
            "proposal_only",
            "review_only",
            "blocked",
        }:
            self.halt()
            raise ValueError("Proposal tools cannot claim execution or verification")
        try:
            for ref in result.artifact_refs:
                if self.verify_artifact(self.principal, self.scope, ref) is not True:
                    raise ValueError("Artifact scope differs")
            self._authorize()
        except Exception:  # noqa: BLE001 -- artifact-store diagnostics are not model-visible
            self.halt()
            raise RuntimeError("Registered artifact ownership unavailable") from None
        for ref in result.artifact_refs:
            kind = ref.split("-", 1)[0]
            if kind in {"evidence", "proposal", "rehearsal"}:
                self.references.setdefault(kind, set()).add(ref)
        return result
