"""Bounded local dispatch of durable environment operation IDs.

This is the explicit single-host service mode, not a hosted SQS consumer.
PostgreSQL claims/intent remain authoritative; a thread is only a wakeup.
"""

import logging
import queue
import threading


class LocalEnvironmentDispatcher:
    def __init__(self, worker_context):
        if not callable(worker_context):
            raise TypeError("Trusted registered worker composition required")
        self.worker_context = worker_context
        self.queue = queue.Queue(maxsize=16)
        self.stopped = threading.Event()
        self.thread = None

    def dispatch(self, operation_id, attempt_id):
        if self.stopped.is_set() or self.thread is None or not self.thread.is_alive():
            raise RuntimeError("Local migration dispatcher is unavailable; durable operation retained")
        self.queue.put_nowait((operation_id, attempt_id))

    def start(self):
        if self.thread is not None or self.stopped.is_set():
            raise RuntimeError("Local migration dispatcher was already started")
        self.thread = threading.Thread(target=self._run, name="sky-environment-worker", daemon=True)
        self.thread.start()

    def _run(self):
        while not self.stopped.is_set():
            try:
                operation_id, attempt_id = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                with self.worker_context() as worker:
                    worker.execute(operation_id, attempt_id)
            except Exception:  # noqa: BLE001 -- no driver errors/secrets; PostgreSQL retains actual state
                logging.getLogger(__name__).warning(
                    "Environment worker stopped without a confirmed outcome; inspect durable operation state"
                )
            finally:
                self.queue.task_done()

    def close(self, *, timeout=5):
        self.stopped.set()
        if self.thread is not None:
            self.thread.join(timeout)
            return not self.thread.is_alive()
        return True
