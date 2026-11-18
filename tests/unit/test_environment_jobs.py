from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock
from uuid import uuid4

import pytest

from application.environment_jobs import EnvironmentJobService, EnvironmentJobWorker, RegisteredEnvironmentJob
from domain.access import LoginSource, Principal, ResourceOwner, Role
from ports.operations import ExecutionLease, Operation
from tests.unit.test_database_transfer import transfer

NOW = datetime(2026, 10, 31, tzinfo=UTC)


@pytest.fixture
def flow():
    actor = Principal("operator", "org", Role.DEPLOYER, LoginSource.PRIVATE_OPERATOR)
    registration = RegisteredEnvironmentJob(
        "game",
        ResourceOwner("org", "operator"),
        transfer(),
        NOW + timedelta(hours=1),
        "http://127.0.0.1:8780/",
        "b" * 64,
    )
    store = Mock()
    history = []
    store.environment_operations.side_effect = lambda *a, **kw: history[:]

    def admit(app, kind, key, command):
        op = Operation(
            str(uuid4()), app, kind, "queued", str(uuid4()), command, {}, None, False, 1, None, None
        )
        history.insert(0, op)
        return op

    store.admit.side_effect = admit
    store.get.side_effect = lambda ref: next((v for v in history if v.id == ref), None)
    store.claim.side_effect = lambda oid, aid, owner, **kw: ExecutionLease(
        oid, aid, owner, 1, NOW + timedelta(minutes=15), "test"
    )
    for name in (
        "heartbeat",
        "begin_external",
        "checkpoint",
        "observe_external",
        "complete",
        "require_attention",
    ):
        getattr(store, name).return_value = True
    resolve = Mock(return_value=actor)
    service = EnvironmentJobService(
        store,
        {"game": registration},
        resolve,
        preflight=Mock(return_value=True),
        dispatch=Mock(),
        clock=lambda: NOW,
    )
    transport, cutover = Mock(), Mock()
    cutover.promote.return_value = {"baseline": {"plan_id": "qualified"}}

    @contextmanager
    def runtime(*a, **kw):
        yield transport, cutover

    worker = EnvironmentJobWorker(service, runtime, owner="registered-worker")
    return service, worker, actor, registration, store, history, transport, cutover, resolve


def submit(flow, **overrides):
    s, _, actor, r, *_ = flow
    return s.submit(
        actor,
        r.id,
        **{
            "action": "transfer",
            "review_revision": r.revision,
            "request_key": "one",
            "confirm_write_pause": True,
            "confirm_websocket_reconnect": True,
            **overrides,
        },
    )


def test_intake_is_async_durable_and_returns_no_secret_or_commands(flow):
    s, _, actor, r, _store, history, transport, cutover, _ = flow
    result = submit(flow)
    assert result["status"] == "queued" and result["dispatch"] == "requested"
    s.dispatch.assert_called_once_with(history[0].id, history[0].attempt_id)
    transport.copy.assert_not_called()
    cutover.promote.assert_not_called()
    assert set(result) == {
        "id",
        "kind",
        "status",
        "requires_reconciliation",
        "stages",
        "dispatch",
        "entrypoint",
    }
    assert s.detail(actor, r.id)["full_v4_qualified"] is False


@pytest.mark.parametrize(
    "change", ["revoked", "foreign", "viewer", "expired", "revision", "pause", "sessions", "preflight"]
)
def test_bad_authority_or_consent_never_admits(flow, change):
    s, _, actor, r, store, *_ = flow
    options = {}
    if change == "revoked":
        s.resolve_principal.return_value = None
    elif change == "foreign":
        actor = replace(actor, organization_id="foreign")
    elif change == "viewer":
        actor = replace(actor, role=Role.VIEWER)
        s.resolve_principal.return_value = actor
    elif change == "expired":
        s.clock = lambda: r.expires_at
    elif change == "revision":
        options["review_revision"] = "a" * 64
    elif change == "pause":
        options["confirm_write_pause"] = False
    elif change == "sessions":
        options["confirm_websocket_reconnect"] = False
    else:
        s.preflight.return_value = False
    altered = (s, flow[1], actor, *flow[3:])
    with pytest.raises((PermissionError, ValueError)):
        submit(altered, **options)
    store.admit.assert_not_called()


def test_failed_wakeup_preserves_queued_operation_and_duplicate_does_not_replay(flow):
    s, _, _, _, store, history, *_ = flow
    s.dispatch.side_effect = OSError("private-url")
    result = submit(flow)
    assert result["dispatch"] == "pending"
    again = submit(flow)
    assert again["id"] == result["id"] and again["dispatch"] == "not_replayed"
    assert len(history) == 1 and store.admit.call_count == 1 and s.dispatch.call_count == 1


def test_worker_claims_then_copies_transfers_and_finishes(flow):
    _, worker, _, _, store, history, transport, cutover, _ = flow
    submit(flow)
    op = history[0]
    assert worker.execute(op.id, op.attempt_id) == {"status": "succeeded"}
    assert transport.copy.call_count == cutover.promote.call_count == store.complete.call_count == 1
    assert store.begin_external.call_count == store.observe_external.call_count == 1


def test_uncertain_result_holds_scope_and_never_blindly_reverses(flow):
    _, worker, _, _, store, history, _, cutover, _ = flow
    submit(flow)
    cutover.promote.side_effect = OSError("commit-response-lost")
    op = history[0]
    assert worker.execute(op.id, op.attempt_id) == {"status": "needs_attention"}
    store.require_attention.assert_called_once()
    store.complete.assert_not_called()
    cutover.rollback.assert_not_called()
    history[0] = replace(op, status="needs_attention", external_pending=True)
    assert worker.execute(op.id, op.attempt_id) == {"status": "not_claimed"}
    assert cutover.promote.call_count == 1


def test_worker_rechecks_expiry_before_any_external_intent(flow):
    s, worker, _, r, store, history, transport, _, _ = flow
    submit(flow)
    s.clock = lambda: r.expires_at
    op = history[0]
    with pytest.raises(ValueError):
        worker.execute(op.id, op.attempt_id)
    store.claim.assert_not_called()
    store.begin_external.assert_not_called()
    transport.copy.assert_not_called()


def test_recover_uses_only_current_successful_durable_transfer_baseline(flow):
    _, worker, _, _, _store, history, transport, cutover, _ = flow
    submit(flow)
    first = history[0]
    baseline = {"plan_id": transfer().document()["plan_id"]}
    history[0] = replace(first, status="succeeded", result={"baseline": baseline})
    submit(flow, action="recover", request_key="recover-one")
    op = history[0]
    assert worker.execute(op.id, op.attempt_id) == {"status": "succeeded"}
    cutover.rollback.assert_called_once()
    assert cutover.rollback.call_args.args[1] == baseline
    transport.copy.assert_not_called()


def test_advanced_history_after_admission_blocks_external_mutations(flow):
    _, worker, _, _, store, history, transport, _, _ = flow
    submit(flow)
    op = history[0]
    history.append(replace(op, id=str(uuid4()), kind="environment_recover", status="succeeded"))
    assert worker.execute(op.id, op.attempt_id) == {"status": "failed"}
    store.begin_external.assert_not_called()
    transport.copy.assert_not_called()


def test_readonly_database_registration_failure_precedes_external_intent(flow):
    _, worker, _, _, store, history, transport, cutover, _ = flow
    submit(flow)
    transport.verify_registration.side_effect = ValueError("Unqualified registered resource")
    op = history[0]
    assert worker.execute(op.id, op.attempt_id) == {"status": "failed"}
    store.begin_external.assert_not_called()
    store.require_attention.assert_not_called()
    store.complete.assert_called_once()
    transport.copy.assert_not_called()
    cutover.promote.assert_not_called()


def test_current_runtime_requires_a_fresh_real_read_and_cannot_reuse_stale_success(flow):
    s, _, actor, r, *_ = flow
    s.observe = Mock(
        return_value={
            "available": True,
            "environment": "onprem",
            "writes_blocked": False,
            "observed_at": NOW.isoformat(),
        }
    )
    assert s.detail(actor, r.id)["runtime"]["environment"] == "onprem"
    s.observe.return_value["observed_at"] = (NOW - timedelta(seconds=60)).isoformat()
    assert s.detail(actor, r.id)["runtime"] == {
        "available": False,
        "environment": "unknown",
        "writes_blocked": None,
    }
    s.observe.side_effect = OSError("postgres-private-password")
    assert s.detail(actor, r.id)["runtime"]["available"] is False
