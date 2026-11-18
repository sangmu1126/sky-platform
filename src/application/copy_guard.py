"""Bound RPC overhead only while streaming an uncommitted DB COPY transaction.

Every normal call rechecks lease/membership. Only COPY chunks may reuse a check
for at most one second. The SQL adapters still call the full guard immediately
before COMMIT. No cloud request, routing change, ACL grant or published result
uses this cache. Unknown effects/connection errors are never retried here.
"""

import time
from threading import Event


class UncommittedCopyGuard:
    def __init__(self, check, *, max_age_seconds=1, clock=time.monotonic):
        if type(max_age_seconds) not in {int, float} or not 0 < max_age_seconds <= 1:
            raise ValueError("At most one second of uncommitted-copy check reuse allowed")
        self.check, self.max_age, self.clock = check, max_age_seconds, clock
        self.checked_at = None
        self.halted = Event()

    def __call__(self):
        if self.halted.is_set():
            raise RuntimeError("Copy execution halted")
        self.check()
        if self.halted.is_set():
            raise RuntimeError("Copy execution halted")
        self.checked_at = self.clock()

    def uncommitted_copy_checkpoint(self):
        if self.halted.is_set():
            raise RuntimeError("Copy execution halted")
        now = self.clock()
        if self.checked_at is None or not 0 <= now - self.checked_at < self.max_age:
            self()
