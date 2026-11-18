"""Compose provider ownership with the exact workload DB and restricted writer.

A shared instance's tags do not establish ownership of every database inside
it. Registered SQL markers and restricted-role privileges are checked separately.
This collector is read-only and never adopts or allocates an application DB.
"""

import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path

from adapters.database.environment_transfer import PostgresEnvironmentTransfer, RegisteredTransferEndpoint
from domain.database_inventory import DatabaseInventoryUnavailable, DatabaseResourceEvidence


class PostgresTransferOwnershipVerifier:
    def __init__(
        self, endpoint, provider_verifier, connect, *, writer_role, marker, clock=lambda: datetime.now(UTC)
    ):
        if (
            not isinstance(endpoint, RegisteredTransferEndpoint)
            or not isinstance(writer_role, str)
            or not re.fullmatch(r"sky_transfer_[a-f0-9]{16,32}", writer_role)
            or not isinstance(marker, str)
            or not re.fullmatch(r"sky-transfer-v1:[a-f0-9]{64}", marker)
        ):
            raise ValueError("Exact owned database and writer registration required")
        self.endpoint, self.provider_verifier, self.connect = endpoint, provider_verifier, connect
        self.writer_role, self.marker, self.clock = writer_role, marker, clock

    def verify(self, placement):
        registration = self.endpoint.inventory
        if placement != registration.resource:
            raise ValueError("Workload ownership placement differs from registration")
        try:
            proof = self.provider_verifier.verify(placement)
            now = self.clock()
            if (
                not isinstance(proof, DatabaseResourceEvidence)
                or proof.placement != placement
                or (proof.server_hostname, proof.server_port) != (registration.hostname, registration.port)
                or not 0 <= (now - proof.observed_at).total_seconds() < 60
                or hashlib.sha256(Path(registration.sslrootcert).read_bytes()).hexdigest()
                != registration.ca_sha256
            ):
                raise ValueError("Current provider and CA proof required")
            with self.connect() as db:
                db.read_only = True
                PostgresEnvironmentTransfer._verify_connection(db, self.endpoint)
                owner = db.execute(
                    "SELECT shobj_description(oid,'pg_database'),pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()"
                ).fetchone()
                role = db.execute(
                    """SELECT shobj_description(oid,'pg_authid'),rolcanlogin,rolinherit,rolsuper,rolcreatedb,
                    rolcreaterole,rolreplication,rolbypassrls,rolconnlimit FROM pg_roles WHERE rolname=%s""",
                    (self.writer_role,),
                ).fetchone()
                if (
                    not owner
                    or owner[0] != self.marker
                    or owner[1] == self.writer_role
                    or not role
                    or role[:8] != (self.marker, True, False, False, False, False, False, False)
                    or type(role[8]) is not int
                    or not 1 <= role[8] <= 100
                ):
                    raise ValueError("Database or restricted writer ownership differs")
                privileges = db.execute(
                    "SELECT has_database_privilege(%s,current_database(),'CONNECT'),"
                    "has_database_privilege(%s,current_database(),'CREATE'),"
                    "has_schema_privilege(%s,'public','USAGE'),has_schema_privilege(%s,'public','CREATE'),"
                    "EXISTS(SELECT 1 FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=%s))",
                    (self.writer_role,) * 5,
                ).fetchone()
                if privileges != (True, False, True, False, False):
                    raise ValueError("Writer privilege boundary differs")
                if db.execute(
                    "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datallowconn AND NOT datistemplate "
                    "AND datname NOT IN (current_database(),'postgres','rdsadmin') "
                    "AND has_database_privilege(%s,oid,'CONNECT'))",
                    (self.writer_role,),
                ).fetchone() != (False,):
                    raise ValueError("Writer can access another workload database")
            digest = hashlib.sha256(
                (proof.evidence_ref + self.marker + self.writer_role).encode()
            ).hexdigest()
            return DatabaseResourceEvidence(
                placement, "DBOWN-" + digest, self.clock(), registration.hostname, registration.port
            )
        except Exception:  # noqa: BLE001 -- SQL/provider diagnostics may contain credentials
            raise DatabaseInventoryUnavailable("Registered workload DB ownership unavailable") from None
