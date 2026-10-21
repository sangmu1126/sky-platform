"""Real Chrome -> HTTP -> PostgreSQL/outbox -> consumer -> preparation journal.

Authentication, queue transport and RDS preparer are synthetic. SQL state and
worker transitions are real; no cloud resources or workload data are changed.
"""

from concurrent.futures import ThreadPoolExecutor
from threading import Event, Lock
from unittest.mock import Mock, patch

import pytest

from adapters.state.postgres import PostgresDeploymentRecordStore
from application.database_promotion_workflow import KIND, PromotionPreparationWorker
from application.outbox import OutboxPublisher
from application.shared_database_consumer import AllocationQueueRouter, SharedDatabaseConsumer
from ports.queue import ReceivedOperation
from tests.contract.test_dedicated_database_admission import persisted as persisted  # noqa: PLC0414
from tests.contract.test_operation_store import count
from tests.contract.test_operation_store import database as database  # noqa: PLC0414
from tests.contract.test_operation_store import store as store  # noqa: PLC0414
from tests.unit.test_database_preparation_browser import run_browser
from tests.unit.test_database_preparation_http import serve_preparation
from tests.unit.test_deployment_writes import principal
from tests.unit.test_operating_review import ID, NOW

pytest_plugins = ["tests.unit.test_dedicated_database_admission"]


@pytest.mark.parametrize("terminal", ["succeeded", "needs_attention"])
def test_chrome_response_loss_preserves_one_sql_operation_and_worker_receipt(
    persisted, admission_setup, registered, store, database, terminal
):
    records = PostgresDeploymentRecordStore(database, workspace=store.workspace)
    snapshot = records.load_job(ID)
    pending = snapshot.record
    pending["operating_proposal"]["status"] = "pending_approval"
    pending["operating_proposal"].pop("approval")
    records.save_job(ID, pending, expected_revision=snapshot.revision)
    policies = {ID: admission_setup[1]}
    trigger, stop, lock = Event(), Event(), Lock()
    polls = []
    observed = Mock(wraps=store)

    def observe(operation_id):
        operation = store.get(operation_id)
        with lock:
            polls.append(operation_id)
            if len(polls) >= 3:
                trigger.set()
        return operation

    observed.get.side_effect = observe
    sent = []
    queue = Mock(publish=Mock(side_effect=sent.append))
    wrong_queue = Mock()
    router = AllocationQueueRouter(store, wrong_queue, wrong_queue, promotion_queue=queue)
    publisher = OutboxPublisher(store, router, "browser-contract-outbox")
    preparer = Mock()

    def prepare(plan, *, operation_id, guard):
        guard()
        assert plan == persisted["plan"]
        if terminal == "needs_attention":
            raise OSError("Synthetic provider outcome unknown; no actual AWS request")
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
    worker = PromotionPreparationWorker(
        records,
        store,
        policies,
        preparer,
        lambda *_: principal(),
        owner="browser-contract-worker",
        clock=lambda: NOW,
    )
    consumer_queue = Mock()
    consumer = SharedDatabaseConsumer(store, consumer_queue, worker, kind=KIND)

    def dispatch_and_consume():
        if not trigger.wait(timeout=30):
            raise AssertionError("Browser did not restore polling before worker execution")
        if stop.is_set():
            return "aborted"
        dispatch = publisher.dispatch_once()
        assert (dispatch.confirmed, dispatch.deferred) == (1, 0)
        assert len(sent) == 1
        consumer_queue.receive.return_value = ReceivedOperation("fixture-receipt", sent[0].message())
        return consumer.consume_once()

    with (
        patch("boto3.client", side_effect=AssertionError("Cloud clients forbidden")),
        ThreadPoolExecutor(max_workers=1) as executor,
        serve_preparation(records, observed, policies, registered[0].source.pool) as (request, _),
    ):
        future = executor.submit(dispatch_and_consume)
        try:
            browser = run_browser(request.origin, "auto", terminal=terminal)
        except BaseException:
            if future.done():
                future.result()
            raise
        finally:
            stop.set()
            trigger.set()
        assert future.result(timeout=10) == terminal
    assert observed.admit.call_count == 2
    assert observed.admit.call_args_list[0] == observed.admit.call_args_list[1]
    operation = store.get(browser["operation_id"])
    assert browser["terminal"] == terminal
    assert operation.status == terminal
    if terminal == "succeeded":
        assert operation.result["promotion_status"] == "not_started"
        assert operation.result["ready_to_cutover"] is False
        assert operation.external_receipt["verified_scope"] == "rds_ownership_network_tls"
    else:
        assert operation.result is None and operation.external_receipt is None
        assert operation.external_pending
        assert operation.checkpoint == {"stage": "target_outcome_uncertain"}
    assert operation.external_intent["operation_id"] == operation.id
    assert operation.command["proposal"]["status"] == "approved"
    assert operation.command["proposal"]["approval"]["user_id"] == "user1"
    assert [
        count(store, database, table) for table in ("operations", "mutation_scopes", "outbox_events")
    ] == [1, 0 if terminal == "succeeded" else 1, 1]
    with database() as connection:
        assert connection.execute(
            "SELECT published_at IS NOT NULL FROM sky_state.outbox_events WHERE workspace=%s",
            (store.workspace,),
        ).fetchall() == [(True,)]
    assert records.load_job(ID).record["workload_database_binding"] == pending["workload_database_binding"]
    assert len(sent) == 1 and sent[0].operation_id == operation.id
    wrong_queue.publish.assert_not_called()
    preparer.prepare.assert_called_once()
    consumer_queue.delete.assert_called_once()
    consumer_queue.extend.assert_called()
