"""A manual approval must not outlive its referenced cost quote."""

from dataclasses import replace
from datetime import datetime, timedelta
from unittest.mock import Mock

import pytest

from application.database_cutover_workflow import PromotionCutoverAdmission
from application.database_promotion_workflow import KIND, PromotionPreparationAdmission
from application.operating_review import OperatingReview
from engine.promotion_policy import PromotionCostQuote
from tests.unit.test_deployment_writes import principal
from tests.unit.test_operating_review import ID, NOW

pytest_plugins = ["tests.unit.test_database_promotion_workflow"]


def later(seconds):
    return (datetime.fromisoformat(NOW) + timedelta(seconds=seconds)).isoformat()


@pytest.fixture
def costed_flow(flow):
    worker, records, policy, operations, preparer, operation, receipt, _resolver = flow
    policy = replace(
        policy,
        isolation_required=True,
        cost_quote=PromotionCostQuote(2500, "registered-quote", later(10)),
    )
    reviews = OperatingReview(records)
    proposal = reviews.review(principal(), ID, policy, now=NOW)
    approved = reviews.approve(principal(), ID, proposal["proposal_id"], policy, now=NOW)
    admission = PromotionPreparationAdmission(
        records, operations, {ID: policy}, enabled=True, clock=lambda: NOW
    )
    admission.admit(principal(), ID, approved["proposal_id"], "costed-prepare")
    operation = replace(operation, command=operations.admit.call_args.args[3])
    operations.get.return_value = operation
    operations.admit.reset_mock()
    receipt["plan_id"] = approved["plan"]["plan_id"]
    worker.policies[ID] = policy
    return worker, records, policy, operations, preparer, operation, receipt


def test_current_quote_allows_preparation(costed_flow):
    worker, _, _, _, preparer, operation, _ = costed_flow
    worker.clock = lambda: later(9)
    assert worker.execute(operation.id, operation.attempt_id)["status"] == "succeeded"
    preparer.prepare.assert_called_once()


@pytest.mark.parametrize("seconds", [10, 11])
def test_expired_quote_blocks_admission_even_with_fresh_health(costed_flow, seconds):
    _, records, policy, operations, _, operation, _ = costed_flow
    admission = PromotionPreparationAdmission(
        records, operations, {ID: policy}, enabled=True, clock=lambda: later(seconds)
    )
    with pytest.raises(ValueError, match="current referenced cost"):
        admission.admit(principal(), ID, operation.command["proposal"]["proposal_id"], "too-late")
    operations.admit.assert_not_called()


@pytest.mark.parametrize("seconds", [10, 11])
def test_queue_delay_cannot_create_resources_after_quote_expiry(costed_flow, seconds):
    worker, _, _, operations, preparer, operation, _ = costed_flow
    worker.clock = lambda: later(seconds)
    assert worker.execute(operation.id, operation.attempt_id)["status"] == "failed"
    operations.begin_external.assert_not_called()
    preparer.prepare.assert_not_called()
    assert operations.complete.call_args.kwargs["succeeded"] is False


def test_expired_quote_after_external_effect_keeps_reconciliation_required(costed_flow):
    worker, _, _, operations, preparer, operation, receipt = costed_flow
    intent = {
        "kind": KIND,
        "operation_id": operation.id,
        "plan_id": receipt["plan_id"],
        "target": receipt["binding"],
    }
    operations.get.return_value = replace(
        operation,
        external_intent=intent,
        external_receipt=receipt,
        checkpoint={"stage": "target_prepared"},
    )
    worker.clock = lambda: later(11)
    assert worker.execute(operation.id, operation.attempt_id)["status"] == "needs_attention"
    operations.require_attention.assert_called_once()
    operations.complete.assert_not_called()
    preparer.prepare.assert_not_called()


def test_replacement_quote_cannot_reuse_previous_approval(costed_flow):
    worker, _, policy, operations, preparer, operation, _ = costed_flow
    worker.policies[ID] = replace(policy, cost_quote=PromotionCostQuote(2500, "new-quote", later(60)))
    worker.clock = lambda: later(11)
    assert worker.execute(operation.id, operation.attempt_id)["status"] == "failed"
    operations.begin_external.assert_not_called()
    preparer.prepare.assert_not_called()


def test_expired_quote_also_blocks_cutover_admission(costed_flow):
    _, records, policy, operations, _, operation, _ = costed_flow
    admission = PromotionCutoverAdmission(
        records, operations, {ID: policy}, {}, enabled=True, clock=lambda: later(11)
    )
    with pytest.raises(ValueError, match="current referenced cost"):
        admission.admit(principal(), ID, operation.command["proposal"]["proposal_id"], "late-cutover")
    operations.admit.assert_not_called()


def test_quote_expiring_during_membership_checks_blocks_preparation(costed_flow):
    worker, _, _, operations, preparer, operation, _ = costed_flow
    current = [NOW]
    worker.clock = lambda: current[0]
    calls = []

    def resolve(user, organization):
        calls.append((user, organization))
        if len(calls) == 2:
            current[0] = later(11)
        return principal()

    worker.resolve_principal = resolve
    assert worker.execute(operation.id, operation.attempt_id)["status"] == "failed"
    operations.begin_external.assert_not_called()
    preparer.prepare.assert_not_called()


@pytest.mark.parametrize("boundary", ["adapter_guard", "adapter_return"])
@pytest.mark.parametrize("change", ["cost", "requester", "approval", "source", "health", "unavailable"])
def test_preparation_rechecks_authorization_during_and_after_adapter(costed_flow, boundary, change):
    from domain.access import Role

    worker, records, _, operations, preparer, operation, receipt = costed_flow
    later_effects = []

    def prepare(_plan, *, operation_id, guard):
        guard()
        if change == "cost":
            worker.clock = lambda: later(10)
        elif change == "requester":
            worker.resolve_principal = lambda *_args: principal(role=Role.VIEWER)
        elif change == "approval":
            records.job["operating_proposal"]["approval"]["proposal_id"] = "revoked"
        elif change == "source":
            records.revision += 1
        elif change == "health":
            records.health[-1]["healthy"] = False
        else:
            worker.resolve_principal = Mock(side_effect=OSError("membership unavailable"))
        if boundary == "adapter_guard":
            guard()
            later_effects.append("must not run")
        return receipt

    preparer.prepare.side_effect = prepare
    assert worker.execute(operation.id, operation.attempt_id)["status"] == "needs_attention"
    assert later_effects == []
    operations.begin_external.assert_called_once()
    operations.interrupt.assert_called_once()
    operations.observe_external.assert_not_called()
    operations.complete.assert_not_called()
