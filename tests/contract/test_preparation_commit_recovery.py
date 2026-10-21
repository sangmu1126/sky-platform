"""Real SQL rollback/commit followed by a lost response must not repeat effects.

Transport, identity and the provider receipt are synthetic. SQL transactions,
lease expiry recovery and worker decisions are real; no cloud calls are made.
"""

from unittest.mock import Mock, patch

import pytest

from adapters.state.operations import PostgresOperationStore
from adapters.state.postgres import PostgresDeploymentRecordStore
from application.database_promotion_workflow import KIND, PromotionPreparationWorker
from application.outbox import OutboxPublisher
from application.shared_database_consumer import AllocationQueueRouter, SharedDatabaseConsumer
from ports.operations import ApplicationBusy
from ports.queue import ReceivedOperation
from tests.contract.test_operation_store import count
from tests.contract.test_operation_store import database as database  # noqa: PLC0414
from tests.contract.test_operation_store import store as store  # noqa: PLC0414
from tests.contract.test_preparation_revalidation import persisted as persisted  # noqa: PLC0414
from tests.contract.test_preparation_revalidation import preparation as preparation  # noqa: PLC0414
from tests.contract.test_preparation_revalidation import revoke
from tests.unit.test_deployment_writes import principal
from tests.unit.test_operating_review import ID, NOW

pytest_plugins = ["tests.unit.test_dedicated_database_admission"]


@pytest.mark.parametrize(
    "boundary,change",
    [
        ("observation_rollback", None),
        ("observation_response_lost", None),
        ("completion_rollback", None),
        ("completion_response_lost", None),
        *(("observation_response_lost", change) for change in ("approval", "membership", "source", "cost")),
    ],
)
def test_ambiguous_database_result_recovers_without_recreating_target(
    preparation, store, database, boundary, change
):
    records, operation, worker, preparer, queue, consumer = preparation
    original_binding = records.load_job(ID).record["workload_database_binding"]

    def prepare(plan, *, operation_id, guard):
        guard()
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
    event = store._event
    observation = store.observe_external
    completion = store.complete

    def fail_event(connection, operation_id, stage):
        if (boundary == "observation_rollback" and stage == "external_observed") or (
            boundary == "completion_rollback" and stage == "succeeded"
        ):
            # Raised within the real transaction, after its UPDATEs. The
            # connection context must roll them back, including scope deletion.
            raise OSError("Synthetic connection failure before commit")
        return event(connection, operation_id, stage)

    def lose_response(method, *args, **kwargs):
        assert method(*args, **kwargs)
        raise OSError("Synthetic response loss after actual commit")

    with patch("boto3.client", side_effect=AssertionError("Cloud clients forbidden")):
        with (
            patch.object(store, "_event", side_effect=fail_event),
            patch.object(
                store,
                "observe_external",
                side_effect=(lambda *a, **kw: lose_response(observation, *a, **kw))
                if boundary == "observation_response_lost"
                else observation,
            ),
            patch.object(
                store,
                "complete",
                side_effect=(lambda *a, **kw: lose_response(completion, *a, **kw))
                if boundary == "completion_response_lost"
                else completion,
            ),
        ):
            assert consumer.consume_once() == "unavailable"
        queue.delete.assert_not_called()
        preparer.prepare.assert_called_once()
        interrupted = store.get(operation.id)
        observed = boundary != "observation_rollback"
        completed = boundary == "completion_response_lost"
        assert interrupted.status == ("succeeded" if completed else "running")
        assert interrupted.external_pending is (not observed)
        assert (interrupted.external_receipt is not None) is observed
        assert count(store, database, "mutation_scopes") == (0 if completed else 1)
        if not completed:
            with pytest.raises(ApplicationBusy):
                store.admit(operation.application_id, "deploy", "premature-replacement", {})
            # Deterministically expire this lease instead of sleeping 15 minutes.
            with database() as connection:
                connection.execute(
                    "UPDATE sky_state.operations SET lease_until=clock_timestamp()-interval '1 second' "
                    "WHERE workspace=%s AND id=%s",
                    (store.workspace, operation.id),
                )

        restarted = PostgresOperationStore(database, workspace=store.workspace)
        assert restarted.recover_expired() == (() if completed else (operation.id,))
        recovered = restarted.get(operation.id)
        sent = []
        publisher = OutboxPublisher(
            restarted,
            AllocationQueueRouter(restarted, None, None, promotion_queue=Mock(publish=sent.append)),
            "commit-recovery-publisher",
        )
        assert publisher.dispatch_once().confirmed == (1 if observed and not completed else 0)
        assert len(sent) == (1 if observed and not completed else 0)
        resumed_preparer = Mock(side_effect=AssertionError("Must not recreate a prepared target"))
        resumed_worker = PromotionPreparationWorker(
            PostgresDeploymentRecordStore(database, workspace=store.workspace),
            restarted,
            worker.policies,
            resumed_preparer,
            lambda *_: principal(),
            owner="commit-recovery-worker",
            clock=lambda: NOW,
        )
        if change is not None:
            revoke(change, resumed_worker.records, resumed_worker)
        resumed_queue = Mock(
            receive=Mock(
                return_value=ReceivedOperation(
                    "recovered-receipt", sent[0].message() if sent else queue.receive.return_value.message
                )
            )
        )
        resumed = SharedDatabaseConsumer(restarted, resumed_queue, resumed_worker, kind=KIND)
        expected = "needs_attention" if change else "succeeded"
        assert resumed.consume_once() == (expected if sent else "duplicate")
        assert resumed.consume_once() == "duplicate"
        final = restarted.get(operation.id)
        assert final.status == ("succeeded" if observed and not change else "needs_attention")
        if observed and not change:
            assert final.result["promotion_status"] == "not_started"
            assert final.result["ready_to_cutover"] is False
            assert final.external_receipt == interrupted.external_receipt
            assert count(store, database, "mutation_scopes") == 0
        else:
            assert final.result is None
            assert final.external_receipt == interrupted.external_receipt
            assert final.external_intent == interrupted.external_intent
            assert final.external_pending
            assert count(store, database, "mutation_scopes") == 1
            with pytest.raises(ApplicationBusy):
                restarted.admit(operation.application_id, "deploy", "unsafe-after-recovery", {})
            if change:
                assert final.checkpoint == {"stage": "revalidation_after_external_effect"}
        assert final.attempt_id == recovered.attempt_id
        assert count(store, database, "operations") == 1
        assert count(store, database, "outbox_events") == (2 if sent else 1)
        assert records.load_job(ID).record["workload_database_binding"] == original_binding
        resumed_preparer.prepare.assert_not_called()
        assert resumed_queue.delete.call_count == 2
