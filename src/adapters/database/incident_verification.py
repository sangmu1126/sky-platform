"""Verify an explicit, trusted table snapshot and test rotated app credentials.

This supports the same bounded table-only schema as promotion copy. A matching
baseline proves equality with that reviewed snapshot, never absence of malicious
business data. LOGIN is opened only for authentication probes, then fenced again.
The composition root must first fence execution and register the exact transport.
"""

import hashlib
import json
import re
import secrets

import psycopg

from adapters.database.promotion_copy import _digest, _inventory


def database_fingerprint(db, binding, *, max_rows=100000, max_bytes=64 * 1024 * 1024):
    if db.execute("SELECT current_database()").fetchone() != (binding.database_name,):
        raise ValueError("Workload snapshot database differs from registration")
    db.execute("SET LOCAL TIME ZONE 'UTC'")
    db.execute("SET LOCAL datestyle='ISO, YMD'")
    tables = _inventory(db)
    if len(tables) > 100:
        raise ValueError("Workload table inventory exceeds verification bound")
    contents = {name: _digest(db, name, max_rows, max_bytes) for name, *_ in tables}
    raw = json.dumps(
        {"schema": tables, "tables": contents}, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class PostgresIncidentVerification:
    def __init__(self, restriction, *, workload_connect, login_connect, cleanup_restriction=None):
        self.cleanup_restriction = cleanup_restriction or restriction
        if (
            self.cleanup_restriction.binding != restriction.binding
            or self.cleanup_restriction.fence.role != restriction.fence.role
            or self.cleanup_restriction.fence.marker != restriction.fence.marker
        ):
            raise ValueError("Cleanup must restrict the exact ownership-marked workload role")
        self.restriction = restriction
        self.binding = restriction.binding
        self.workload_connect, self.login_connect = workload_connect, login_connect

    def verify(self, *, candidate_password, previous_password, expected_fingerprint, guard):
        if (
            not isinstance(candidate_password, str)
            or len(candidate_password) < 32
            or not isinstance(previous_password, str)
            or not previous_password
            or secrets.compare_digest(candidate_password, previous_password)
            or not isinstance(expected_fingerprint, str)
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", expected_fingerprint)
        ):
            raise ValueError("Distinct credentials and reviewed snapshot fingerprint required")
        guard()
        observed = self.restriction.inspect(guard=guard)
        if observed["login_enabled"] is not False or observed["active_sessions"] != 0:
            raise ValueError("Restricted drained workload required for credential verification")
        with self.workload_connect() as db:
            db.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            db.execute("SET LOCAL statement_timeout='30s'")
            before = database_fingerprint(db, self.binding)
            if before != expected_fingerprint:
                raise ValueError("Workload differs from reviewed integrity baseline")
        guard()
        try:
            self.restriction.fence.set_login(True, guard=guard)
            guard()
            # Reject only an actual PostgreSQL password failure. Timeout, TLS or
            # NOLOGIN errors do not demonstrate old-password invalidation.
            try:
                with self.login_connect(previous_password):
                    pass
            except psycopg.OperationalError as error:
                if not password_authentication_failed(error, self.restriction.fence.role):
                    raise ValueError("Old password rejection was not an authentication failure") from None
            else:
                raise ValueError("Previous workload password remains usable")
            guard()
            with self.login_connect(candidate_password) as db:
                db.execute("SET TRANSACTION READ ONLY")
                if db.execute("SELECT current_user,current_database()").fetchone() != (
                    self.restriction.fence.role,
                    self.binding.database_name,
                ):
                    raise ValueError("Candidate authenticated to a different workload")
            guard()
        finally:
            # Cleanup must still run if membership/metadata changed during a
            # probe. Its only permitted action restricts this ownership-marked
            # role and drains sessions; it cannot grant access or resume work.
            self.cleanup_restriction.fence.set_login(False, guard=lambda: None)
        guard()
        final = self.restriction.inspect(guard=guard)
        if final["login_enabled"] is not False or final["active_sessions"] != 0:
            raise ValueError("Post-verification workload restriction not confirmed")
        with self.workload_connect() as db:
            db.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            db.execute("SET LOCAL statement_timeout='30s'")
            if database_fingerprint(db, self.binding) != before:
                raise ValueError("Workload changed during credential verification")
        guard()
        return {
            "baseline_fingerprint": before,
            "baseline_matched": True,
            "authentication_verified": True,
            "previous_password_rejected": True,
            "login_enabled": False,
            "active_sessions": 0,
            "credentials_activated": False,
            "recovery_authorized": False,
        }


def password_authentication_failed(error, role):
    if getattr(error, "sqlstate", None) == "28P01":
        return True
    # libpq does not expose SQLSTATE for connection-startup failures. Support
    # only its known English server diagnostic; other locales remain unknown.
    # This is used only over the operator-registered authenticated transport.
    pgconn = getattr(error, "pgconn", None)
    raw = getattr(pgconn, "error_message", None)
    return (
        isinstance(raw, bytes)
        and len(raw) <= 8192
        and re.search(
            rb'FATAL:\s+password authentication failed for user "'
            + re.escape(role.encode())
            + rb'"(?:\r?\n|$)',
            raw,
        )
        is not None
    )
