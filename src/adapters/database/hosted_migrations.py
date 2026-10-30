"""Immutable migration ledger under the application role, never the pool administrator."""

import hashlib
import threading

from adapters.database.migrations import collect_sql_migrations


def apply_hosted_migrations(project, connect, *, guard, timeout_seconds=10):
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 30:
        raise ValueError("Bounded migration deadline required")
    bundle = collect_sql_migrations(project)
    guard()
    connection = connect()
    expired = threading.Event()

    def cancel():
        expired.set()
        try:
            connection.cancel()
        except Exception:  # noqa: BLE001 -- callback must never print SQL/credential diagnostics
            expired.set()  # Keep the boundary closed without logging provider diagnostics.

    timer = threading.Timer(timeout_seconds, cancel)
    timer.daemon = True
    try:
        timer.start()
        with connection:
            # Role-level timeouts are defaults, not an isolation guarantee.
            # The independent caller deadline still cancels SET statement_timeout=0.
            connection.execute("SET LOCAL statement_timeout = '5s'")
            connection.execute("SET LOCAL lock_timeout = '2s'")
            row = connection.execute(
                "SELECT rolsuper,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=current_user"
            ).fetchone()
            if row is None or any(row):
                raise PermissionError("Application migration role must have no administrative capabilities")
            connection.execute("SELECT pg_advisory_xact_lock(hashtext(current_database()), 0)")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS sky_schema_migrations (name text PRIMARY KEY,sha256 text NOT NULL)"
            )
            known = dict(connection.execute("SELECT name,sha256 FROM sky_schema_migrations").fetchall())
            expected = {m.name: m.sha256 for m in bundle.migrations}
            if any(expected.get(name) != checksum for name, checksum in known.items()):
                raise ValueError("Previously applied schema migrations changed or disappeared")
            for migration in bundle.migrations:
                guard()
                raw = (bundle.directory / migration.name).read_bytes()
                if hashlib.sha256(raw).hexdigest() != migration.sha256 or expired.is_set():
                    raise ValueError("Migration changed or exceeded its deadline")
                if migration.name not in known:
                    connection.execute(raw.decode(), prepare=False)
                    connection.execute(
                        "INSERT INTO sky_schema_migrations(name,sha256) VALUES (%s,%s)",
                        (migration.name, migration.sha256),
                    )
            guard()
            if expired.is_set():
                raise TimeoutError("Application migration deadline exceeded")
            if collect_sql_migrations(project).digest != bundle.digest:
                raise ValueError("Migration bundle changed during execution")
        return {
            "protocol": "app-role-schema-v1",
            "bundle_digest": bundle.digest,
            "migrations": len(bundle.migrations),
            "replayed": len(known),
            "credentials_persisted": False,
        }
    finally:
        timer.cancel()
        timer.join(timeout=2)
        connection.close()
