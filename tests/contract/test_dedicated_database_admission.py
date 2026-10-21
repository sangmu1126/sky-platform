"""Operator CLI -> real PostgreSQL operation/outbox -> existing queue router.

Queue delivery is simulated. No AWS or workload database clients are created.
"""

import json
from unittest.mock import Mock

import pytest

from adapters.state.postgres import PostgresDeploymentRecordStore
from application.outbox import OutboxPublisher
from application.shared_database_consumer import AllocationQueueRouter
from interfaces.b_runtime import main
from tests.contract.test_operation_store import count
from tests.contract.test_operation_store import database as database  # noqa: PLC0414
from tests.contract.test_operation_store import store as store  # noqa: PLC0414
from tests.unit.test_dedicated_database_admission import arguments, runtime
from tests.unit.test_operating_review import ID

pytest_plugins = ["tests.unit.test_dedicated_database_admission"]


@pytest.fixture
def persisted(admission_setup, store, database, monkeypatch):
    memory, _, approved = admission_setup
    monkeypatch.setenv("SKY_STATE_WORKSPACE", store.workspace)
    records = PostgresDeploymentRecordStore(database, workspace=store.workspace)
    records.save_job(ID, memory.job, expected_revision=None)
    records.save_health(ID, memory.health, expected_revision=None)
    return approved


def test_cli_duplicate_admission_and_uncertain_queue_send_use_one_durable_attempt(
    persisted, store, database, capsys
):
    with runtime(database):
        main(arguments(persisted))
        first = json.loads(capsys.readouterr().out)
        main(arguments(persisted))
        second = json.loads(capsys.readouterr().out)
    assert first == second
    assert [
        count(store, database, table) for table in ("operations", "mutation_scopes", "outbox_events")
    ] == [1, 1, 1]
    operation = store.get(first["operation_id"])
    assert operation.command["proposal"] == persisted and operation.status == "queued"
    queue, wrong_queue = Mock(), Mock(side_effect=AssertionError("Wrong queue"))
    router = AllocationQueueRouter(store, wrong_queue, wrong_queue, promotion_queue=queue)
    publisher = OutboxPublisher(store, router, "contract-publisher")
    queue.publish.side_effect = OSError("SQS may have accepted the send")
    result = publisher.dispatch_once()
    assert (result.confirmed, result.deferred) == (0, 1)
    first_delivery = queue.publish.call_args.args[0]
    with database() as connection:
        connection.execute(
            "UPDATE sky_state.outbox_events SET available_at=clock_timestamp() WHERE workspace=%s",
            (store.workspace,),
        )
    queue.publish.side_effect = None
    result = publisher.dispatch_once()
    assert (result.confirmed, result.deferred) == (1, 0)
    delivery = queue.publish.call_args.args[0]
    assert delivery.message() == first_delivery.message()
    assert delivery.operation_id == first["operation_id"] and delivery.attempt_id == first["attempt_id"]
    assert set(delivery.message()) == {"version", "workspace", "application_id", "operation_id", "attempt_id"}
    wrong_queue.publish.assert_not_called()
    assert publisher.dispatch_once().confirmed == 0
    assert store.get(operation.id).external_intent is None


def test_busy_app_admission_rolls_back_operation_and_outbox(persisted, store, database, capsys):
    store.admit("game", "deploy", "other-operation", {"source": "registered"})
    with runtime(database), pytest.raises(SystemExit) as error:
        main(arguments(persisted))
    assert error.value.code == 1
    assert capsys.readouterr().out == ""
    assert [
        count(store, database, table) for table in ("operations", "mutation_scopes", "outbox_events")
    ] == [1, 1, 1]
