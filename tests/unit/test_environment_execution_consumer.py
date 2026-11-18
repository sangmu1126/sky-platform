"""The reviewed environment queue acknowledges only durable terminal state."""

import threading
from dataclasses import replace
from unittest.mock import Mock
from uuid import uuid4

import pytest

from application.environment_execution_consumer import ReviewedEnvironmentExecutionConsumer
from application.shared_database_consumer import AllocationQueueRouter
from interfaces.environment_execution_consumer import (
    require_isolated_environment_queue,
    run_reviewed_environment_consumer,
)
from ports.operations import Operation, OutboxDelivery
from ports.queue import ReceivedOperation


@pytest.fixture
def flow():
    operation = Operation(
        str(uuid4()),
        "app",
        "environment_transfer",
        "queued",
        str(uuid4()),
        {
            "profile": "registered_environment_execution_v1",
            "registration_id": "reviewed-app",
        },
        {},
        None,
        False,
        1,
        None,
        None,
    )
    current = [operation]
    store = Mock(workspace="workspace", get=Mock(side_effect=lambda _ref: current[0]))
    queue = Mock(
        receive=Mock(
            return_value=ReceivedOperation(
                "receipt",
                {
                    "version": 1,
                    "workspace": "workspace",
                    "operation_id": operation.id,
                    "attempt_id": operation.attempt_id,
                    "application_id": "app",
                },
            )
        )
    )
    worker = Mock()

    def execute(_operation_id, _attempt_id):
        current[0] = replace(current[0], status="succeeded")
        return {"status": "succeeded"}

    worker.execute.side_effect = execute
    consumer = ReviewedEnvironmentExecutionConsumer(
        store,
        queue,
        worker,
        heartbeat_seconds=300,
    )
    return consumer, store, queue, worker, operation, current


def test_consumer_extends_visibility_executes_and_acknowledges_durable_success(flow):
    consumer, store, queue, worker, operation, _current = flow
    assert consumer.consume_once() == "succeeded"
    store.recover_expired.assert_called_once_with(limit=10)
    queue.extend.assert_called_once_with(queue.receive.return_value, seconds=900)
    worker.execute.assert_called_once_with(operation.id, operation.attempt_id)
    queue.delete.assert_called_once_with(queue.receive.return_value)


@pytest.mark.parametrize("status", ["succeeded", "failed", "needs_attention"])
def test_terminal_or_stale_delivery_is_acknowledged_without_reexecution(flow, status):
    consumer, _store, queue, worker, operation, current = flow
    current[0] = replace(operation, status=status, external_pending=status == "needs_attention")
    assert consumer.consume_once() == "duplicate"
    queue.delete.assert_called_once()
    queue.extend.assert_not_called()
    worker.execute.assert_not_called()


@pytest.mark.parametrize("change", ["message", "workspace", "application", "kind", "running"])
def test_foreign_or_nonqueued_delivery_is_deferred_without_execution(flow, change):
    consumer, store, queue, worker, operation, current = flow
    if change == "message":
        queue.receive.return_value = ReceivedOperation("receipt", {"version": 1})
    elif change == "workspace":
        queue.receive.return_value.message["workspace"] = "foreign"
    elif change == "application":
        current[0] = replace(operation, application_id="other")
    elif change == "kind":
        current[0] = replace(operation, kind="deploy")
    else:
        current[0] = replace(operation, status="running")
    assert consumer.consume_once() in {
        "invalid",
        "foreign_workspace",
        "foreign_operation",
        "busy",
    }
    worker.execute.assert_not_called()
    queue.delete.assert_not_called()
    queue.extend.assert_called_once_with(queue.receive.return_value, seconds=60)
    store.recover_expired.assert_called_once()


def test_worker_return_without_durable_terminal_state_is_not_acknowledged(flow):
    consumer, _store, queue, worker, _operation, _current = flow
    worker.execute.side_effect = None
    worker.execute.return_value = {"status": "succeeded"}
    assert consumer.consume_once() == "busy"
    queue.delete.assert_not_called()
    assert [value.kwargs["seconds"] for value in queue.extend.call_args_list] == [900, 60]


def test_worker_or_visibility_failure_never_acknowledges(flow):
    consumer, _store, queue, worker, _operation, _current = flow
    worker.execute.side_effect = OSError("private worker failure")
    assert consumer.consume_once() == "unavailable"
    queue.delete.assert_not_called()
    assert [value.kwargs["seconds"] for value in queue.extend.call_args_list] == [900, 60]

    queue.reset_mock()
    worker.reset_mock()
    queue.extend.side_effect = OSError("private queue failure")
    assert consumer.consume_once() == "unavailable"
    worker.execute.assert_not_called()
    queue.delete.assert_not_called()


def test_environment_outbox_requires_its_own_queue(flow):
    _consumer, store, default, _worker, operation, current = flow
    delivery = OutboxDelivery(
        "event",
        "publisher",
        1,
        operation.id,
        operation.attempt_id,
        operation.application_id,
        store.workspace,
    )
    with pytest.raises(OSError, match="Required operation queue"):
        AllocationQueueRouter(store, default, Mock()).publish(delivery)
    environment = Mock()
    AllocationQueueRouter(store, default, Mock(), environment_queue=environment).publish(delivery)
    environment.publish.assert_called_once_with(delivery)
    default.publish.assert_not_called()
    current[0] = replace(operation, command={"profile": "legacy_environment_job"})
    AllocationQueueRouter(store, default, Mock(), environment_queue=environment).publish(delivery)
    default.publish.assert_called_once_with(delivery)
    environment.publish.assert_called_once()


def test_hosted_loop_requires_isolated_fifo_queue_and_honors_once():
    url = "https://sqs.ap-northeast-2.amazonaws.com/111111111111/sky-environment.fifo"
    assert require_isolated_environment_queue(url, ("https://example.invalid/other",)) == url
    with pytest.raises(ValueError, match="Dedicated"):
        require_isolated_environment_queue(url, (url,))
    consumer = Mock(consume_once=Mock(return_value="idle"))
    assert run_reviewed_environment_consumer(consumer, threading.Event(), once=True) == "idle"
    consumer.consume_once.assert_called_once()
