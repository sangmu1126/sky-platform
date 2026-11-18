"""Consume reviewed environment operations from one isolated hosted queue."""

import threading
from contextlib import contextmanager
from uuid import UUID

from application.environment_execution_worker import KIND


def _message(value):
    fields = {"version", "workspace", "operation_id", "attempt_id", "application_id"}
    if not isinstance(value, dict) or set(value) != fields or value["version"] != 1:
        raise ValueError("Exact environment queue identity message required")
    for field in ("operation_id", "attempt_id"):
        if not isinstance(value[field], str) or str(UUID(value[field])) != value[field]:
            raise ValueError("Canonical environment queue operation identity required")
    for field in ("workspace", "application_id"):
        item = value[field]
        if not isinstance(item, str) or not 1 <= len(item) <= 128:
            raise ValueError("Bounded environment queue scope required")
    return value


class ReviewedEnvironmentExecutionConsumer:
    def __init__(self, operations, queue, worker, *, heartbeat_seconds=30):
        if not all(
            callable(value)
            for value in (
                getattr(operations, "get", None),
                getattr(operations, "recover_expired", None),
                getattr(queue, "receive", None),
                getattr(queue, "extend", None),
                getattr(queue, "delete", None),
                getattr(worker, "execute", None),
            )
        ):
            raise TypeError("Environment operation store, queue and worker required")
        if type(heartbeat_seconds) is not int or not 1 <= heartbeat_seconds <= 300:
            raise ValueError("Bounded environment queue heartbeat required")
        self.operations = operations
        self.queue = queue
        self.worker = worker
        self.heartbeat_seconds = heartbeat_seconds

    @contextmanager
    def visibility(self, delivery):
        self.queue.extend(delivery, seconds=900)
        stop = threading.Event()

        def heartbeat():
            while not stop.wait(self.heartbeat_seconds):
                try:
                    self.queue.extend(delivery, seconds=900)
                except Exception:  # noqa: BLE001 -- DB lease still prevents a second effect owner
                    return

        thread = threading.Thread(
            target=heartbeat,
            name="sky-reviewed-environment-visibility",
            daemon=True,
        )
        thread.start()
        try:
            yield
        finally:
            stop.set()
            thread.join(timeout=min(self.heartbeat_seconds, 30))

    def _defer(self, delivery, *, seconds):
        try:
            self.queue.extend(delivery, seconds=seconds)
        except Exception:  # noqa: BLE001 -- leave the delivery for queue redelivery/DLQ policy
            return False
        return True

    def consume_once(self):
        self.operations.recover_expired(limit=10)
        delivery = self.queue.receive()
        if delivery is None:
            return "idle"
        try:
            message = _message(delivery.message)
        except (TypeError, ValueError):
            self._defer(delivery, seconds=60)
            return "invalid"
        if message["workspace"] != self.operations.workspace:
            self._defer(delivery, seconds=60)
            return "foreign_workspace"
        try:
            operation = self.operations.get(message["operation_id"])
        except Exception:  # noqa: BLE001 -- do not acknowledge unknown state or disclose diagnostics
            self._defer(delivery, seconds=60)
            return "unavailable"
        if operation.application_id != message["application_id"] or operation.kind != KIND:
            self._defer(delivery, seconds=60)
            return "foreign_operation"
        if operation.attempt_id != message["attempt_id"] or operation.status in {
            "succeeded",
            "failed",
            "needs_attention",
        }:
            self.queue.delete(delivery)
            return "duplicate"
        if operation.status != "queued" or operation.external_pending:
            self._defer(delivery, seconds=60)
            return "busy"
        try:
            with self.visibility(delivery):
                self.worker.execute(operation.id, operation.attempt_id)
            saved = self.operations.get(operation.id)
            if saved.attempt_id != operation.attempt_id or saved.status in {
                "succeeded",
                "failed",
                "needs_attention",
            }:
                self.queue.delete(delivery)
                return saved.status if saved.attempt_id == operation.attempt_id else "duplicate"
            self._defer(delivery, seconds=60)
            return "busy"
        except Exception:  # noqa: BLE001 -- never acknowledge an unconfirmed worker/queue outcome
            self._defer(delivery, seconds=60)
            return "unavailable"
