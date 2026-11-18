"""Registered app migration intake and leased worker, shared by local HTTP/queues.

Only operator registrations supply runtime factories, baseline and endpoint.
HTTP/queue input supplies opaque IDs. This narrow TUG profile does not certify
all V4 preservation gates, AI conversion or arbitrary-app/session migration.
"""

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

from application.copy_guard import UncommittedCopyGuard
from application.database_cutover import OperationCutoverJournal
from domain.access import Action, Principal, ResourceOwner, permitted
from domain.database_transfer import RegisteredDatabaseTransfer

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
_ACTIONS = {"transfer": "environment_transfer", "recover": "environment_recover"}


@dataclass(frozen=True)
class RegisteredEnvironmentJob:
    id: str
    owner: ResourceOwner
    transfer: RegisteredDatabaseTransfer
    expires_at: datetime
    entrypoint: str
    input_sha256: str
    profile: str = "reviewed_tug_round_drain_v1"

    def __post_init__(self):
        url = urlsplit(self.entrypoint)
        if (
            not _ID.fullmatch(self.id)
            or not isinstance(self.owner, ResourceOwner)
            or not isinstance(self.transfer, RegisteredDatabaseTransfer)
            or self.transfer.source.organization_id != self.owner.organization_id
            or self.expires_at.tzinfo is None
            or not re.fullmatch(r"[a-f0-9]{64}", self.input_sha256)
            or self.profile != "reviewed_tug_round_drain_v1"
            or url.scheme not in {"http", "https"}
            or not url.hostname
            or url.username
            or url.password
            or url.fragment
            or url.query
            or (url.scheme == "http" and url.hostname not in {"127.0.0.1", "localhost", "::1"})
            or any(ord(c) <= 32 for c in self.entrypoint)
        ):
            raise ValueError("Owned fixed game migration registration required")

    @property
    def revision(self):
        return hashlib.sha256(
            json.dumps(
                {
                    "id": self.id,
                    "owner": self.owner.record(),
                    "plan": self.transfer.document(),
                    "expires_at": self.expires_at.isoformat(),
                    "entrypoint": self.entrypoint,
                    "input_sha256": self.input_sha256,
                    "profile": self.profile,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()


class EnvironmentJobService:
    def __init__(
        self, operations, registrations, resolve_principal, *, preflight, dispatch, clock=None, observe=None
    ):
        self.operations, self.registrations = operations, dict(registrations)
        self.resolve_principal, self.preflight, self.dispatch = resolve_principal, preflight, dispatch
        self.clock = clock or (lambda: datetime.now(UTC))
        self.observe = observe
        if any(
            not isinstance(r, RegisteredEnvironmentJob) or key != r.id
            for key, r in self.registrations.items()
        ):
            raise ValueError("Trusted environment job registrations required")

    def authorize(self, principal, reference, action):
        r = self.registrations.get(reference)
        if not isinstance(principal, Principal) or r is None or not permitted(principal, action, r.owner):
            raise PermissionError("Registered application is unavailable")
        current = self.resolve_principal(principal.user_id, principal.organization_id)
        if current != principal or not permitted(current, action, r.owner):
            raise PermissionError("Current deployment membership required")
        return r

    def _history(self, registration):
        return self.operations.environment_operations(registration.transfer.source.application_id, limit=20)

    def detail(self, principal, reference):
        r = self.authorize(principal, reference, Action.READ)
        history = self._history(r)
        observed = {"available": False, "environment": "unknown", "writes_blocked": None}
        if self.observe is not None:
            try:
                current = self.observe(r)
                if (
                    not isinstance(current, dict)
                    or set(current) != {"available", "environment", "writes_blocked", "observed_at"}
                    or current["available"] is not True
                    or current["environment"] not in {"aws", "onprem"}
                    or type(current["writes_blocked"]) is not bool
                ):
                    raise ValueError()
                stamp = datetime.fromisoformat(current["observed_at"])
                if stamp.tzinfo is None or not 0 <= (self.clock() - stamp).total_seconds() < 60:
                    raise ValueError()
                observed = dict(current)
            except Exception:  # noqa: BLE001 -- old observations never become current availability
                observed = {"available": False, "environment": "unknown", "writes_blocked": None}
        self.authorize(principal, reference, Action.READ)
        return {
            "id": r.id,
            "application_id": r.transfer.source.application_id,
            "review_revision": r.revision,
            "expires_at": r.expires_at.isoformat(),
            "execution_available": self.clock() < r.expires_at
            and permitted(principal, Action.DEPLOY, r.owner),
            "entrypoint": r.entrypoint,
            "profile": r.profile,
            "runtime": observed,
            "write_pause_required": True,
            "websocket_reconnect_required": True,
            "zero_downtime": False,
            "full_v4_qualified": False,
            "operations": [self.public_operation(v) for v in history],
        }

    @staticmethod
    def public_operation(operation):
        steps = operation.checkpoint.get("cutover_steps", [])
        return {
            "id": operation.id,
            "kind": operation.kind,
            "status": operation.status,
            "requires_reconciliation": operation.status == "needs_attention" or operation.external_pending,
            "stages": [
                {"stage": v["stage"], "status": v["status"]}
                for v in steps
                if isinstance(v, dict)
                and isinstance(v.get("stage"), str)
                and re.fullmatch(r"[a-z_]{1,64}", v["stage"])
                and v.get("status") in {"intent", "observed"}
            ][-30:],
        }

    def list(self, principal):
        values = []
        for reference in self.registrations:
            try:
                values.append(self.detail(principal, reference))
            except PermissionError:
                continue
        return values

    def submit(
        self,
        principal,
        reference,
        *,
        action,
        review_revision,
        request_key,
        confirm_write_pause,
        confirm_websocket_reconnect,
    ):
        if (
            action not in _ACTIONS
            or not isinstance(request_key, str)
            or not _ID.fullmatch(request_key)
            or confirm_write_pause is not True
            or confirm_websocket_reconnect is not True
        ):
            raise ValueError("Explicit write pause and WebSocket reconnect consent required")
        r = self.authorize(principal, reference, Action.DEPLOY)
        if r.revision != review_revision or self.clock() >= r.expires_at:
            raise ValueError("Migration review changed or expired")
        history = self._history(r)
        duplicate = next((v for v in history if v.command.get("request_key") == request_key), None)
        if duplicate is not None:
            if (
                duplicate.command.get("action") != action
                or duplicate.command.get("registration_revision") != review_revision
                or duplicate.command.get("created_by") != principal.user_id
            ):
                raise ValueError("Migration request key was used for a different request")
            return {
                **self.public_operation(duplicate),
                "dispatch": "not_replayed",
                "entrypoint": r.entrypoint,
            }
        previous = next((v for v in history if v.status == "succeeded"), None)
        if action == "recover" and (previous is None or previous.kind != "environment_transfer"):
            raise ValueError("A successful current transfer is required before recovery")
        if action == "transfer" and previous is not None and previous.kind != "environment_recover":
            raise ValueError("Inspect current target before another transfer")
        if self.preflight(r, action) is not True:
            raise ValueError("Registered game runtime is not ready for migration")
        self.authorize(principal, reference, Action.DEPLOY)
        command = {
            "schema_version": 1,
            "registration_id": r.id,
            "registration_revision": r.revision,
            "organization_id": principal.organization_id,
            "created_by": principal.user_id,
            "request_key": request_key,
            "action": action,
            "previous_operation_id": previous.id if previous else None,
            "write_pause_consent": True,
            "websocket_reconnect_consent": True,
        }
        operation = self.operations.admit(
            r.transfer.source.application_id, _ACTIONS[action], request_key, command
        )
        # Admission and outbox persist first. A failed wakeup leaves a queued ID;
        # never report failure as permission to create a different operation.
        wakeup = "not_needed"
        if operation.status == "queued":
            try:
                self.dispatch(operation.id, operation.attempt_id)
                wakeup = "requested"
            except Exception:  # noqa: BLE001 -- preserve durable queued work, never leak transport credentials
                wakeup = "pending"
        return {**self.public_operation(operation), "dispatch": wakeup, "entrypoint": r.entrypoint}


class EnvironmentJobWorker:
    def __init__(self, service, runtime, *, owner):
        self.service, self.runtime, self.owner = service, runtime, owner

    def execute(self, operation_id, attempt_id):
        s, store = self.service, self.service.operations
        operation = store.get(operation_id)
        if (
            operation is None
            or operation.attempt_id != attempt_id
            or operation.kind not in _ACTIONS.values()
            or operation.status != "queued"
        ):
            return {"status": "not_claimed"}
        c = operation.command
        if set(c) != {
            "schema_version",
            "registration_id",
            "registration_revision",
            "organization_id",
            "created_by",
            "request_key",
            "action",
            "previous_operation_id",
            "write_pause_consent",
            "websocket_reconnect_consent",
        }:
            raise ValueError("Persisted migration command is invalid")
        principal = s.resolve_principal(c["created_by"], c["organization_id"])
        r = s.authorize(principal, c["registration_id"], Action.DEPLOY)
        if (
            c["schema_version"] != 1
            or c["action"] not in _ACTIONS
            or _ACTIONS[c["action"]] != operation.kind
            or c["registration_revision"] != r.revision
            or c["write_pause_consent"] is not True
            or c["websocket_reconnect_consent"] is not True
            or operation.application_id != r.transfer.source.application_id
            or s.clock() >= r.expires_at
        ):
            raise ValueError("Migration registration or consent changed")
        lease = store.claim(operation.id, operation.attempt_id, self.owner, seconds=900)
        if lease is None:
            return {"status": "not_claimed"}
        journal = OperationCutoverJournal(store, lease, effect_kind=operation.kind)

        def check():
            journal.guard()
            if s.authorize(principal, r.id, Action.DEPLOY) != r or s.clock() >= r.expires_at:
                raise PermissionError("Migration execution authorization expired")

        guard = UncommittedCopyGuard(check)
        begun = False
        try:
            guard()
            if s.preflight(r, c["action"]) is not True:
                raise ValueError("Current game runtime differs from review")
            previous = store.get(c["previous_operation_id"]) if c["previous_operation_id"] else None
            latest = next((v for v in s._history(r) if v.status == "succeeded"), None)
            if (latest.id if latest else None) != (previous.id if previous else None):
                raise ValueError("Migration history advanced after admission")
            if previous is not None and (
                previous.application_id != operation.application_id
                or previous.status != "succeeded"
                or previous.command.get("registration_revision") != r.revision
                or previous.kind
                != ("environment_transfer" if c["action"] == "recover" else "environment_recover")
            ):
                raise ValueError("Durable previous migration result differs")
            if c["action"] == "recover" and previous is None:
                raise ValueError("Recovery baseline required")
            with self.runtime(r, guard=guard, journal=journal) as (transport, flow):
                # Ownership/TLS/locale rejection is known to have no copy or
                # traffic effect. It should fail cleanly without trapping the
                # app in an uncertain mutation scope.
                transport.verify_registration(r.transfer, guard=guard)
                # Any failure from begin onward may have committed externally.
                begun = True
                journal.begin(r.transfer.document())
                if c["action"] == "recover":
                    result = flow.rollback(r.transfer, previous.result["baseline"])
                else:
                    journal({"stage": "initial_copy", "status": "intent"})
                    baseline = (
                        transport.refresh(
                            r.transfer, expected_destination=previous.result["baseline"], guard=guard
                        )
                        if previous
                        else transport.copy(r.transfer, guard=guard)
                    )
                    journal({"stage": "initial_copy", "status": "observed"})
                    result = flow.promote(r.transfer, baseline)
                guard()
                journal.finish(result)
            return {"status": "succeeded"}
        except Exception:  # noqa: BLE001 -- unknown effects retain scope and never replay automatically
            guard.halted.set()
            if begun:
                journal.hold()
                return {"status": "needs_attention"}
            store.complete(lease, {"code": "migration_preflight_failed"}, succeeded=False)
            return {"status": "failed"}
