"""Replace a marked app password only while NOLOGIN and without app sessions."""

from dataclasses import asdict

from psycopg import sql

from adapters.database.incident_restriction import PostgresIncidentRestriction


class PostgresIncidentCredentialPreparation:
    def __init__(self, restriction):
        if not isinstance(restriction, PostgresIncidentRestriction):
            raise TypeError("A registered application restriction is required")
        self.restriction, self.binding = restriction, restriction.binding

    def prepare_password(self, password, *, guard):
        if not isinstance(password, str) or len(password) < 32 or "\0" in password:
            raise ValueError("Fresh in-memory application credentials required")
        guard()
        before = self.restriction.inspect(guard=guard)
        if before["login_enabled"] is not False or before["active_sessions"] != 0:
            raise ValueError("Restricted application with drained sessions required")
        fence = self.restriction.fence
        with fence.connect() as db:
            db.execute("SET LOCAL lock_timeout='5s'")
            db.execute("SET LOCAL statement_timeout='30s'")
            fence._verify_ownership(db)
            if db.execute("SELECT rolcanlogin FROM pg_roles WHERE rolname=%s", (fence.role,)).fetchone() != (
                False,
            ):
                raise ValueError("Application login must remain disabled")
            if db.execute(
                "SELECT count(*) FROM pg_stat_activity WHERE usename=%s AND datname=%s",
                (fence.role, self.binding.database_name),
            ).fetchone() != (0,):
                raise ValueError("Application sessions must remain drained")
            guard()
            verifier = db.pgconn.encrypt_password(
                password.encode(), fence.role.encode(), b"scram-sha-256"
            ).decode()
            db.execute(
                sql.SQL("ALTER ROLE {} NOLOGIN PASSWORD {}").format(
                    sql.Identifier(fence.role), sql.Literal(verifier)
                )
            )
        # A lost commit response is never retried by this adapter.
        guard()
        after = self.restriction.inspect(guard=guard)
        if after["login_enabled"] is not False or after["active_sessions"] != 0:
            raise ValueError("Credential preparation must preserve the application restriction")
        return {
            "binding": asdict(self.binding),
            "password_update_acknowledged": True,
            "login_enabled": False,
            "active_sessions": 0,
            "authentication_verified": False,
        }
