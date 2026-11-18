"""Registered AWS/VM PostgreSQL snapshot transport, never an execution authority.

Resource verification, certificate/hostname/role pinning and bounded freshness
precede all data mutations. A local tunnel is explicitly registered separately
from the actual resource port; its certificate must still verify the real host.
This is a write-pause transport, not CDC or a zero-downtime implementation.
"""

import ipaddress
from dataclasses import dataclass
from datetime import UTC, datetime

from adapters.database.migration_inventory import PostgresInventoryRegistration
from adapters.database.promotion_sync import PostgresPromotionSynchronizer
from adapters.runtime.pinned_ca import pinned_ca_bundle
from domain.database_inventory import DatabaseResourceEvidence
from domain.database_transfer import RegisteredDatabaseTransfer


@dataclass(frozen=True)
class RegisteredTransferEndpoint:
    inventory: PostgresInventoryRegistration
    connect_port: int
    connect_hostaddr: str | None = None

    def __post_init__(self):
        if not isinstance(self.inventory, PostgresInventoryRegistration):
            raise TypeError("Pinned database inventory registration required")
        if type(self.connect_port) is not int or not 1 <= self.connect_port <= 65535:
            raise ValueError("Explicit bounded connection port required")
        if self.connect_hostaddr not in {None, "127.0.0.1", "::1"}:
            raise ValueError("Only explicitly registered loopback tunnels are supported")
        if self.connect_port != self.inventory.port and self.connect_hostaddr is None:
            raise ValueError("A forwarded port requires an explicit loopback transport")


class PostgresEnvironmentTransfer(PostgresPromotionSynchronizer):
    def __init__(
        self,
        transfer,
        source_endpoint,
        target_endpoint,
        source_connect,
        target_connect,
        source_verifier,
        target_verifier,
        *,
        clock=lambda: datetime.now(UTC),
        max_rows=100000,
        max_bytes=64 * 1024 * 1024,
    ):
        if not isinstance(transfer, RegisteredDatabaseTransfer):
            raise TypeError("Typed operator database transfer registration required")
        if not all(
            isinstance(item, RegisteredTransferEndpoint) for item in (source_endpoint, target_endpoint)
        ):
            raise TypeError("Pinned transfer endpoints required")
        if (source_endpoint.inventory.resource, target_endpoint.inventory.resource) != (
            transfer.source,
            transfer.target,
        ):
            raise ValueError("Transport endpoints differ from registered placements")
        super().__init__(source_connect, target_connect, max_rows=max_rows, max_bytes=max_bytes)
        self.transfer = transfer
        self.endpoints = (source_endpoint, target_endpoint)
        self.verifiers = (source_verifier, target_verifier)
        self.clock = clock

    def _registered(self, transfer, guard):
        if not isinstance(transfer, RegisteredDatabaseTransfer) or transfer != self.transfer:
            raise ValueError("Database transfer registration changed")
        guard()
        for endpoint, verifier in zip(self.endpoints, self.verifiers):
            registration = endpoint.inventory
            resource = verifier.verify(registration.resource)
            now = self.clock()
            if (
                not isinstance(resource, DatabaseResourceEvidence)
                or resource.placement != registration.resource
                or (resource.server_hostname, resource.server_port)
                != (registration.hostname, registration.port)
                or not isinstance(now, datetime)
                or now.tzinfo is None
                or not 0 <= (now - resource.observed_at).total_seconds() < 60
            ):
                raise ValueError("Current registered resource verification required")
            try:
                pinned_ca_bundle(registration.sslrootcert, registration.ca_sha256)
            except ValueError:
                raise ValueError("Transfer CA certificate changed")
            guard()

    @staticmethod
    def _verify_connection(db, endpoint):
        registration = endpoint.inventory
        expected = {
            "host": registration.hostname,
            "port": str(endpoint.connect_port),
            "user": registration.login_role,
            "dbname": registration.resource.database_name,
            "sslmode": "verify-full",
            "sslrootcert": registration.sslrootcert,
        }
        params = db.info.get_parameters()
        mismatches = [key for key, value in expected.items() if params.get(key) != value]
        if not db.pgconn.ssl_in_use:
            mismatches.append("tls_in_use")
        # Psycopg resolves host into hostaddr even when the caller didn't supply
        # an override. For a registered tunnel pin the override exactly. Direct
        # DNS endpoints remain authenticated by verify-full's pinned hostname;
        # literal IP endpoints must resolve to that same IP.
        actual_address = params.get("hostaddr") or None
        address_mismatch = (
            actual_address != endpoint.connect_hostaddr if endpoint.connect_hostaddr is not None else False
        )
        if endpoint.connect_hostaddr is None and actual_address is not None:
            try:
                literal_host = ipaddress.ip_address(registration.hostname)
            except ValueError:
                literal_host = None
            if literal_host is not None:
                address_mismatch = actual_address != str(literal_host)
        if address_mismatch:
            mismatches.append("hostaddr")
        if mismatches:
            # Field names only: never include role/password/DSN or driver errors.
            raise ValueError(
                "Transfer connection differs from registered TLS transport: " + ",".join(mismatches)
            )
        db.execute("SET LOCAL statement_timeout='5s'")
        db.execute("SET LOCAL lock_timeout='1s'")
        row = db.execute(
            """SELECT current_database(),current_user,current_setting('server_version_num')::integer,
                pg_encoding_to_char(d.encoding),d.datcollate,d.datctype
                FROM pg_database d WHERE d.datname=current_database()"""
        ).fetchone()
        if (
            not row
            or row[:2] != (registration.resource.database_name, registration.login_role)
            or row[2] // 10000 != registration.resource.postgres_major
        ):
            raise ValueError("Transfer database, role or actual major version differs")
        extensions = db.execute(
            "SELECT extname,extversion FROM pg_extension ORDER BY extname LIMIT 33"
        ).fetchall()
        if extensions != [("plpgsql", "1.0")]:
            raise ValueError("Transfer supports only the qualified PostgreSQL extension profile")
        return row[3:]

    def _verify_connections(self, source, target):
        locales = [
            self._verify_connection(db, endpoint) for db, endpoint in zip((source, target), self.endpoints)
        ]
        if locales[0] != locales[1]:
            raise ValueError("Transfer database encoding or locale names differ")

    def verify_registration(self, transfer, *, guard):
        """Read-only ownership, TLS and locale check before recording a copy intent."""
        self._registered(transfer, guard)
        with self.source_connect() as source, self.target_connect() as target:
            source.read_only = True
            target.read_only = True
            self._verify_connections(source, target)
            guard()
        return {"plan_id": transfer.document()["plan_id"], "registration_verified": True, "mutation": False}

    def copy(self, transfer, *, guard):
        self._registered(transfer, guard)
        return self._copy_registered_snapshot(
            transfer.document(),
            transfer.source,
            transfer.target,
            guard=guard,
            verify_connections=self._verify_connections,
        )

    def refresh(self, transfer, *, expected_destination, guard, reverse=False):
        self._registered(transfer, guard)
        if type(reverse) is not bool:
            raise ValueError("Explicit transfer direction required")
        plan = transfer.document()
        if (
            not isinstance(expected_destination, dict)
            or any(expected_destination.get(key) != plan[key] for key in ("plan_id", "source", "target"))
            or expected_destination.get("source_retained") is not True
            or expected_destination.get("routing_changed") is not False
            or expected_destination.get("ready_to_cutover") is not False
            or expected_destination.get("requires_final_write_freeze") is not True
            or expected_destination.get("verified_scope")
            not in {
                "locked_table_snapshot_copy",
                "final_locked_refresh",
                "reverse_recovery_copy",
            }
        ):
            raise ValueError("Exact registered transfer baseline required")
        return self._refresh_registered_snapshot(
            plan,
            transfer.source,
            transfer.target,
            expected_destination=expected_destination,
            guard=guard,
            reverse=reverse,
            verify_connections=self._verify_connections,
        )
