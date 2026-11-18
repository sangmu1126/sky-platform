"""Read-only PostgreSQL metadata, bound to verified resource and TLS registration.

Only operator code constructs registrations and the resource verifier. This is
not a user-controlled DSN endpoint. Shared copy schema restrictions are reused;
this collector does not infer application access or safe cutover from SQL.
"""

import hashlib
import json
import time
from dataclasses import dataclass
from datetime import UTC
from pathlib import Path

from adapters.database.promotion_copy import _inventory
from adapters.runtime.pinned_ca import pinned_ca_bundle
from domain.database_inventory import (
    DatabaseInventory,
    DatabaseInventoryUnavailable,
    DatabaseResourceEvidence,
    aware_time,
)
from domain.database_migration import DatabasePlacement, _reference


@dataclass(frozen=True)
class PostgresInventoryRegistration:
    resource: DatabasePlacement
    hostname: str
    port: int
    login_role: str
    sslrootcert: str
    ca_sha256: str

    def __post_init__(self):
        from datetime import datetime

        DatabaseResourceEvidence(self.resource, "registration", datetime.now(UTC), self.hostname, self.port)
        _reference(self.login_role, "inventory login role")
        if not isinstance(self.sslrootcert, str) or not Path(self.sslrootcert).is_absolute():
            raise ValueError("Explicit CA certificate path required")
        if (
            not isinstance(self.ca_sha256, str)
            or len(self.ca_sha256) != 64
            or any(c not in "0123456789abcdef" for c in self.ca_sha256)
        ):
            raise ValueError("Pinned CA digest required")


class PostgresMigrationInventory:
    def __init__(
        self,
        registration,
        *,
        connect,
        resource_verifier,
        clock,
        metadata_budget_seconds,
        monotonic=time.monotonic,
    ):
        if not isinstance(registration, PostgresInventoryRegistration):
            raise TypeError("Operator inventory registration required")
        if type(metadata_budget_seconds) is not int or not 1 <= metadata_budget_seconds <= 60:
            raise ValueError("Explicit bounded metadata collection budget required")
        self.registration, self.connect = registration, connect
        self.resource_verifier, self.clock = resource_verifier, clock
        self.budget, self.monotonic = metadata_budget_seconds, monotonic

    def inspect(self, placement, *, plan_id):
        # Registration mismatch must fail before calling any external dependency.
        if placement != self.registration.resource:
            raise ValueError("Inventory placement differs from registration")
        try:
            return self._inspect(placement, plan_id)
        except Exception:  # noqa: BLE001 -- provider callbacks can include credential-bearing diagnostics
            # Even provider or connect errors may embed secret-bearing URLs.
            raise DatabaseInventoryUnavailable("Registered database inventory unavailable") from None

    def _inspect(self, placement, plan_id):
        registration = self.registration
        deadline = self.monotonic() + self.budget

        def guard():
            if self.monotonic() >= deadline:
                raise TimeoutError("Metadata collection budget exceeded")

        resource = self.resource_verifier.verify(placement)
        guard()
        if not isinstance(resource, DatabaseResourceEvidence) or (
            resource.placement,
            resource.server_hostname,
            resource.server_port,
        ) != (placement, registration.hostname, registration.port):
            raise ValueError("Verified resource differs from inventory registration")
        try:
            pinned_ca_bundle(registration.sslrootcert, registration.ca_sha256)
        except ValueError:
            raise ValueError("Inventory CA certificate changed")
        with self.connect() as db:
            guard()
            params = db.info.get_parameters()
            if not db.pgconn.ssl_in_use or any(
                params.get(key) != value
                for key, value in {
                    "sslmode": "verify-full",
                    "sslrootcert": registration.sslrootcert,
                    "host": registration.hostname,
                    "port": str(registration.port),
                    "user": registration.login_role,
                    "dbname": placement.database_name,
                }.items()
            ):
                raise ValueError("Inventory connection does not match pinned TLS registration")
            db.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            db.execute("SET LOCAL statement_timeout='5s'")
            db.execute("SET LOCAL lock_timeout='1s'")
            db.execute("SET LOCAL search_path=pg_catalog")
            metadata = db.execute("""SELECT current_database(),current_user,
                current_setting('server_version_num')::integer,pg_encoding_to_char(d.encoding),
                d.datcollate,d.datctype FROM pg_database d WHERE d.datname=current_database()""").fetchone()
            if not metadata or metadata[:2] != (placement.database_name, registration.login_role):
                raise ValueError("Connected database or active role differs from registration")
            guard()
            extensions = tuple(
                db.execute(
                    'SELECT extname,extversion FROM pg_extension ORDER BY extname COLLATE "C" LIMIT 33'
                ).fetchall()
            )
            guard()
            count = db.execute("""SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='public' AND c.relkind='r'""").fetchone()[0]
            guard()
            objects = db.execute("""SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='public'""").fetchone()[0]
            schema_status, fingerprint = "unsupported", None
            if count <= 100 and objects <= 400:
                try:
                    schema = _inventory(db, guard=guard)
                except ValueError:
                    pass  # An explicitly unsupported schema is different from a query failure.
                else:
                    if len(schema) != count:
                        raise ValueError("Schema inventory count differs")
                    schema_status = "supported"
                    fingerprint = hashlib.sha256(json.dumps(schema, sort_keys=True).encode()).hexdigest()
        guard()
        observed_at = self.clock()
        aware_time(observed_at)
        return DatabaseInventory(
            plan_id,
            placement,
            resource,
            observed_at,
            metadata[2],
            extensions,
            count,
            schema_status,
            fingerprint,
            metadata[3],
            metadata[4],
            metadata[5],
        )
