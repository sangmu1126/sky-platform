"""Nonblocking per-app timer exclusion on a dedicated PostgreSQL session.

No schema migration or expiring takeover: close/crash releases the session lock.
An in-flight telemetry read cannot be revoked; callers check the guard before
persisting a review and retain CAS. This does not fence external cloud mutations.
"""

import hashlib
import json
import re
import sys
from contextlib import closing, contextmanager


class PostgresOperatingReviewLocks:
    def __init__(self, connection_factory, *, workspace="team"):
        if not isinstance(workspace, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", workspace):
            raise ValueError("Invalid operating review workspace")
        self.connection_factory, self.workspace = connection_factory, workspace

    def _key(self, organization_id, application_id):
        for value in (organization_id, application_id):
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", value):
                raise ValueError("Invalid operating review scope")
        value = json.dumps(["sky.operating-review.v1", self.workspace, organization_id, application_id])
        return int.from_bytes(hashlib.sha256(value.encode()).digest()[:8], "big", signed=True)

    @contextmanager
    def acquire(self, organization_id, application_id):
        import psycopg

        key = self._key(organization_id, application_id)
        active = False
        try:
            # The factory must open a new connection, never return a pooled session.
            with closing(self.connection_factory()) as connection:
                connection.autocommit = True
                held = connection.execute("SELECT pg_try_advisory_lock(%s)", (key,)).fetchone()
                if held != (True,):
                    yield None
                    return
                active = True

                def guard():
                    if not active or connection.closed:
                        raise OSError("Operating review lock is no longer held")
                    try:
                        if connection.execute("SELECT 1").fetchone() != (1,):
                            raise OSError("Operating review lock check failed")
                    except psycopg.Error:
                        raise OSError("Operating review lock connection lost") from None

                try:
                    yield guard
                finally:
                    active = False
                    failed = sys.exc_info()[0] is not None
                    if not connection.closed:
                        try:
                            released = connection.execute("SELECT pg_advisory_unlock(%s)", (key,)).fetchone()
                            if released != (True,) and not failed:
                                raise OSError("Operating review lock release uncertain")
                        except psycopg.Error:
                            if not failed:
                                raise OSError("Operating review lock release unavailable") from None
        except psycopg.Error:
            raise OSError("Operating review coordination unavailable") from None
