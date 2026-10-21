"""Persist interrupted preparation and terminal redelivery against real PostgreSQL.

Identity, time, queue transport and provider effects are synthetic. No RDS is
created: this checks durable fencing/recovery, not cancellation of cloud calls.
"""

from copy import deepcopy
from dataclasses import replace
from unittest.mock import Mock, patch

import pytest

from adapters.state.postgres import PostgresDeploymentRecordStore
from application.database_promotion_workflow import (
    KIND,
    PromotionPreparationAdmission,
    PromotionPreparationWorker,
)
from application.outbox import OutboxPublisher
from application.shared_database_consumer import AllocationQueueRouter, SharedDatabaseConsumer
from domain.access import Role
from ports.operations import ApplicationBusy
from ports.queue import ReceivedOperation
from tests.contract.test_dedicated_database_admission import persisted as persisted  # noqa: PLC0414
from tests.contract.test_operation_store import count
from tests.contract.test_operation_store import database as database  # noqa: PLC0414
from tests.contract.test_operation_store import store as store  # noqa: PLC0414
from tests.unit.test_deployment_writes import principal
from tests.unit.test_operating_review import ID, NOW

pytest_plugins = ["tests.unit.test_dedicated_database_admission"]


@pytest.fixture
def preparation(persisted, admission_setup, store, database):
    records = PostgresDeploymentRecordStore(database, workspace=store.workspace)
    policies = {ID: admission_setup[1]}
    operation = PromotionPreparationAdmission(
        records, store, policies, enabled=True, clock=lambda: NOW
    ).admit(principal(), ID, persisted["proposal_id"], "interrupted-preparation")
    preparer = Mock()
    worker = PromotionPreparationWorker(
        records,
        store,
        policies,
        preparer,
        lambda *_: principal(),
        owner="revalidation-contract",
        clock=lambda: NOW,
    )
    sent = []
    transport = Mock(publish=Mock(side_effect=sent.append))
    wrong_queue = Mock()
    publisher = OutboxPublisher(
        store,
        AllocationQueueRouter(store, wrong_queue, wrong_queue, promotion_queue=transport),
        "revalidation-contract-outbox",
    )
    assert publisher.dispatch_once().confirmed == 1
    assert len(sent) == 1
    wrong_queue.publish.assert_not_called()
    queue = Mock(receive=Mock(return_value=ReceivedOperation("synthetic-receipt", sent[0].message())))
    consumer = SharedDatabaseConsumer(store, queue, worker, kind=KIND)
    return records, operation, worker, preparer, queue, consumer


def revoke(change, records, worker):
    if change == "cost":
        policy = worker.policies[ID]
        worker.policies[ID] = replace(
            policy, cost_quote=replace(policy.cost_quote, evidence_ref="replacement-quote")
        )
    elif change == "membership":
        worker.resolve_principal = lambda *_: principal(role=Role.VIEWER)
    elif change == "unavailable":
        worker.resolve_principal = Mock(side_effect=OSError("membership unavailable"))
    else:
        snapshot = records.load_job(ID)
        record = snapshot.record
        if change == "approval":
            record["operating_proposal"]["approval"]["proposal_id"] = "revoked"
        else:
            record["source_digest"] = "e" * 64
        records.save_job(ID, record, expected_revision=snapshot.revision)


@pytest.mark.parametrize("change", ["cost", "membership", "approval", "source"])
def test_revocation_before_external_intent_releases_scope_and_acknowledges_failure(
    preparation, store, database, change
):
    records, operation, worker, preparer, queue, consumer = preparation
    revoke(change, records, worker)
    with patch("boto3.client", side_effect=AssertionError("Cloud clients forbidden")):
        assert consumer.consume_once() == "failed"
        assert consumer.consume_once() == "duplicate"
    saved = store.get(operation.id)
    assert saved.status == "failed"
    assert saved.external_intent is None and saved.external_receipt is None
    assert saved.result == {"code": "promotion_revalidation_failed"}
    assert count(store, database, "mutation_scopes") == 0
    assert count(store, database, "outbox_events") == 1
    preparer.prepare.assert_not_called()
    assert queue.delete.call_count == 2
    # Failure before effects permits a distinct operation for this app.
    assert store.admit(operation.application_id, "deploy", "after-failure", {}).status == "queued"


def test_membership_outage_before_intent_requeues_without_releasing_app_scope(preparation, store, database):
    records, operation, worker, preparer, queue, consumer = preparation
    revoke("unavailable", records, worker)
    with patch("boto3.client", side_effect=AssertionError("Cloud clients forbidden")):
        assert consumer.consume_once() == "interrupted"
        saved = store.get(operation.id)
        assert saved.status == "queued" and saved.attempt_id != operation.attempt_id
        assert saved.external_intent is None and saved.external_receipt is None
        assert saved.checkpoint == {"stage": "source_read_unavailable"}
        assert count(store, database, "mutation_scopes") == 1
        assert count(store, database, "outbox_events") == 2
        queue.delete.assert_not_called()
        queue.extend.assert_called()
        # Redelivery of the old attempt must not consume the recovery attempt.
        assert consumer.consume_once() == "duplicate"
    assert store.get(operation.id) == saved
    preparer.prepare.assert_not_called()
    queue.delete.assert_called_once()
    with pytest.raises(ApplicationBusy):
        store.admit(operation.application_id, "deploy", "during-recovery", {})
    assert count(store, database, "operations") == 1


@pytest.mark.parametrize("boundary", ["adapter_guard", "adapter_return"])
@pytest.mark.parametrize("change", ["cost", "membership", "approval", "source", "unavailable"])
def test_revocation_after_intent_retains_scope_and_never_replays_preparation(
    preparation, store, database, boundary, change
):
    records, operation, worker, preparer, queue, consumer = preparation
    original_binding = deepcopy(records.load_job(ID).record["workload_database_binding"])
    later_effects = []

    def prepare(plan, *, operation_id, guard):
        guard()
        revoke(change, records, worker)
        if boundary == "adapter_guard":
            guard()
            later_effects.append("must not run")
        return {
            "operation_id": operation_id,
            "plan_id": plan["plan_id"],
            "binding": plan["target"],
            "status": "available",
            "verified_scope": "rds_ownership_network_tls",
            "encrypted": True,
            "publicly_accessible": False,
            "resource_id": "db-" + "A" * 26,
        }

    preparer.prepare.side_effect = prepare
    with patch("boto3.client", side_effect=AssertionError("Cloud clients forbidden")):
        assert consumer.consume_once() == "needs_attention"
        saved = store.get(operation.id)
        assert saved.status == "needs_attention" and saved.external_pending
        assert saved.external_intent["operation_id"] == operation.id
        assert saved.external_intent["plan_id"] == operation.command["proposal"]["plan"]["plan_id"]
        assert saved.external_receipt is None and saved.result is None
        assert saved.checkpoint == {"stage": "target_outcome_uncertain"}
        assert count(store, database, "mutation_scopes") == 1
        assert store.recover_expired() == ()
        assert consumer.consume_once() == "duplicate"
        assert worker.execute(operation.id, operation.attempt_id)["status"] == "needs_attention"
    assert store.get(operation.id) == saved
    with pytest.raises(ApplicationBusy):
        store.admit(operation.application_id, "deploy", "unsafe-replacement", {})
    assert count(store, database, "operations") == 1
    assert count(store, database, "outbox_events") == 1
    assert records.load_job(ID).record["workload_database_binding"] == original_binding
    assert later_effects == []
    preparer.prepare.assert_called_once()
    assert queue.delete.call_count == 2
    with database() as connection:
        states = connection.execute(
            "SELECT stage FROM sky_state.operation_events WHERE workspace=%s",
            (store.workspace,),
        ).fetchall()
    assert ("needs_attention",) in states
    assert ("succeeded",) not in states and ("requeued",) not in states
