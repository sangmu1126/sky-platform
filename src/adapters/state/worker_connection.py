"""One explicitly scoped worker connection with short, separate transactions.

This isn't an API connection pool. A serial worker can avoid repeating TLS/SCRAM
for every lease heartbeat while each call still commits/rolls back its own DB
transaction. No SQL/commit or dead connection is automatically retried.
"""

from contextlib import contextmanager
from threading import RLock


class ScopedWorkerConnection:
    def __init__(self, connect):
        self.connect, self.connection = connect, None
        self.lock, self.in_use = RLock(), False

    def __enter__(self):
        with self.lock:
            if self.connection is not None:
                raise RuntimeError("Worker connection scope already open")
            self.connection = self.connect()
            if self.connection.autocommit:
                self.connection.close()
                self.connection = None
                raise ValueError("Transactional worker connection required")
            return self

    @contextmanager
    def __call__(self):
        with self.lock:
            if self.connection is None or self.connection.closed:
                raise OSError("Worker DB connection unavailable; reconcile before reopening")
            if self.in_use:
                raise RuntimeError("Nested worker DB borrowing is not supported")
            self.in_use = True
            try:
                with self.connection.transaction():
                    yield self.connection
            finally:
                self.in_use = False

    def __exit__(self, *_error):
        with self.lock:
            if self.connection is not None:
                self.connection.close()
            self.connection = None
