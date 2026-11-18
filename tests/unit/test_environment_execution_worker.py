"""Reviewed environment operations revalidate before any registered effect."""

from dataclasses import replace
from datetime import timedelta
from unittest.mock import Mock
from uuid import uuid4

import pytest

from application.environment_admission import environment_execution_command
from application.environment_execution_worker import RegisteredEnvironmentExecutionWorker
from ports.operations import ExecutionLease, Operation
from tests.unit.test_environment_admission import actor, gate, registered
from tests.unit.test_environment_transition import NOW


@pytest.fixture
def flow():
    execution = registered()
    principal = actor()
    record = gate(execution)
    command = environment_execution_command(
        principal,
        execution,
        review_id=str(uuid4()),
        report_id="ENV-" + "a" * 64,
        gate_record_id=record["record_id"],
        request_key="reviewed-transfer-one",
        confirm_write_pause=True,
        confirm_websocket_reconnect=True,
    )
    operation = Operation(
        str(uuid4()),
        execution.job.transfer.source.application_id,
        "environment_transfer",
        "queued",
        str(uuid4()),
        command,
        {},
        None,
        False,
        1,
        None,
        None,
    )
    store = Mock()
    current = [operation]
    store.get.side_effect = lambda _operation_id: current[0]
    store.claim.return_value = ExecutionLease(
        operation.id,
        operation.attempt_id,
        "reviewed-worker",
        1,
        NOW + timedelta(minutes=15),
        "test",
    )
    for name in (
        "heartbeat",
        "checkpoint",
        "begin_external",
        "observe_external",
        "complete",
        "require_attention",
    ):
        getattr(store, name).return_value = True
    admission = Mock(revalidate=Mock(return_value=True))
    resources = Mock(
        verify=Mock(
            return_value={
                "execution_revision": execution.revision,
                "verified": True,
                "evidence_refs": ["WPI-" + "a" * 64, "WRI-" + "b" * 64],
            }
        )
    )
    effect = Mock(return_value={"result_ref": "environment-result"})
    resolver = Mock(return_value=principal)
    worker = RegisteredEnvironmentExecutionWorker(
        store,
        admission,
        {execution.job.id: execution},
        resolver,
        resources,
        effect,
        owner="reviewed-worker",
        clock=lambda: NOW,
    )
    return worker, execution, principal, operation, current, store, admission, resources, effect, resolver


def test_worker_revalidates_and_persists_resource_ownership_before_effect(flow):
    worker, execution, _principal, operation, _current, store, admission, resources, effect, _ = flow
    assert worker.execute(operation.id, operation.attempt_id) == {"status": "succeeded"}
    assert admission.revalidate.call_count >= 3
    resources.verify.assert_called_once()
    effect.assert_called_once()
    store.begin_external.assert_called_once()
    intent = store.begin_external.call_args.args[1]
    assert intent["kind"] == "environment_transfer"
    assert intent["plan"]["execution_revision"] == execution.revision
    first_checkpoint = store.checkpoint.call_args_list[0].args[1]
    assert first_checkpoint["cutover_steps"][0]["stage"] == "resource_ownership"
    store.observe_external.assert_called_once()
    store.complete.assert_called_once()
    store.require_attention.assert_not_called()


@pytest.mark.parametrize("change", ["revision", "consent", "kind", "registration"])
def test_changed_persisted_command_never_claims_or_executes(flow, change):
    worker, _execution, _principal, operation, current, store, _admission, _resources, effect, _ = flow
    if change == "kind":
        current[0] = replace(operation, kind="environment_recover")
    else:
        command = dict(operation.command)
        field, value = {
            "revision": ("registration_revision", "f" * 64),
            "consent": ("write_pause_consent", False),
            "registration": ("registration_id", "other-registration"),
        }[change]
        command[field] = value
        current[0] = replace(operation, command=command)
    if change == "kind":
        assert worker.execute(operation.id, operation.attempt_id) == {"status": "not_claimed"}
    elif change == "registration":
        with pytest.raises(ValueError, match="unavailable"):
            worker.execute(operation.id, operation.attempt_id)
    else:
        with pytest.raises(ValueError, match="Persisted reviewed"):
            worker.execute(operation.id, operation.attempt_id)
    store.claim.assert_not_called()
    effect.assert_not_called()


def test_revoked_membership_or_admission_never_reaches_claim(flow):
    worker, _execution, _principal, operation, _current, store, admission, _resources, effect, resolver = flow
    resolver.return_value = None
    with pytest.raises(PermissionError, match="Current reviewed"):
        worker.execute(operation.id, operation.attempt_id)
    store.claim.assert_not_called()
    effect.assert_not_called()
    resolver.return_value = actor()
    admission.revalidate.side_effect = PermissionError("review revoked")
    with pytest.raises(PermissionError, match="review revoked"):
        worker.execute(operation.id, operation.attempt_id)
    store.claim.assert_not_called()


def test_resource_ownership_failure_is_terminal_without_external_intent(flow):
    worker, _execution, _principal, operation, _current, store, _admission, resources, effect, _ = flow
    resources.verify.side_effect = OSError("private provider detail")
    assert worker.execute(operation.id, operation.attempt_id) == {"status": "failed"}
    store.begin_external.assert_not_called()
    store.complete.assert_called_once_with(
        store.claim.return_value,
        {"code": "environment_execution_precondition_failed"},
        succeeded=False,
    )
    effect.assert_not_called()


def test_uncertain_effect_is_held_and_never_replayed(flow):
    worker, _execution, _principal, operation, current, store, _admission, _resources, effect, _ = flow
    effect.side_effect = OSError("provider response lost")
    assert worker.execute(operation.id, operation.attempt_id) == {"status": "needs_attention"}
    store.require_attention.assert_called_once()
    store.complete.assert_not_called()
    current[0] = replace(operation, status="needs_attention", external_pending=True)
    assert worker.execute(operation.id, operation.attempt_id) == {"status": "not_claimed"}
    assert effect.call_count == 1


def test_authority_loss_after_intent_is_uncertain_not_failed_or_retried(flow):
    worker, _execution, _principal, operation, _current, store, admission, _resources, effect, _ = flow
    admission.revalidate.side_effect = [True, True, True, PermissionError("membership changed")]

    def external_effect(_execution, *, guard, journal):
        guard()
        raise AssertionError("guard should stop before another effect")

    effect.side_effect = external_effect
    assert worker.execute(operation.id, operation.attempt_id) == {"status": "needs_attention"}
    store.require_attention.assert_called_once()
    store.complete.assert_not_called()
