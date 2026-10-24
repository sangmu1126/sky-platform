"""Disable only an ownership-marked app login and drain its DB sessions.

Caller must separately quiesce application traffic and fence orchestration.
Admin/other writers are not covered by this login fence.
"""

from dataclasses import asdict

from psycopg import sql


class PostgresApplicationFence:
    def __init__(self, connect, binding, login_role, ownership_marker, *, administrative_database=None):
        if not login_role.startswith(("sky_login_", "sky_dedicated_")) or not ownership_marker.startswith(
            ("sky-pool-allocation-v1:", "sky-dedicated-access-v1:")
        ):
            raise ValueError("Registered application identity required")
        self.connect, self.binding, self.role, self.marker = connect, binding, login_role, ownership_marker
        self.administrative_database = administrative_database or binding.database_name
        if (
            self.administrative_database != binding.database_name
            and not self.administrative_database.startswith("sky_pool_")
        ):
            raise ValueError("Only registered workload or pool administration database allowed")

    def _verify_ownership(self, db):
        if db.execute("SELECT current_database()").fetchone() != (self.administrative_database,):
            raise ValueError("Fence database differs from binding")
        identity = db.execute(
            "SELECT shobj_description(oid,'pg_authid'),rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=%s",
            (self.role,),
        ).fetchone()
        database_row = db.execute(
            "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=%s",
            (self.binding.database_name,),
        ).fetchone()
        database_marker = database_row[0] if database_row else None
        membership = db.execute(
            "SELECT count(*) FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=%s)",
            (self.role,),
        ).fetchone()[0]
        if (
            identity != (self.marker, False, False, False, False, False)
            or database_marker != self.marker
            or membership
        ):
            raise ValueError("Fence role is unowned or privileged")

    def set_login(self, enabled, *, guard):
        if type(enabled) is not bool:
            raise ValueError("Explicit login state required")
        if self.binding.role not in {
            "shared_workload",
            "dedicated_workload",
        } or self.binding.database_name.startswith("sky_pool_"):
            raise ValueError("Only workload database login may be fenced")
        guard()
        with self.connect() as db:
            db.execute("SET LOCAL lock_timeout='5s'")
            db.execute("SET LOCAL statement_timeout='30s'")
            self._verify_ownership(db)
            guard()
            db.execute(
                sql.SQL("ALTER ROLE {} {}").format(
                    sql.Identifier(self.role), sql.SQL("LOGIN" if enabled else "NOLOGIN")
                )
            )
        # Commit NOLOGIN before terminating sessions: no reconnect window.
        if not enabled:
            guard()
            with self.connect() as db:
                db.execute("SET LOCAL statement_timeout='30s'")
                db.execute(
                    "SELECT pg_terminate_backend(pid,5000) FROM pg_stat_activity WHERE datname=%s AND usename=%s AND pid<>pg_backend_pid()",
                    (self.binding.database_name, self.role),
                ).fetchall()
                db.execute("SELECT pg_stat_clear_snapshot()")
                if db.execute(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname=%s AND usename=%s AND pid<>pg_backend_pid()",
                    (self.binding.database_name, self.role),
                ).fetchone()[0]:
                    raise ValueError("Application sessions have not drained; keep traffic closed")
        guard()
        return {"binding": asdict(self.binding), "login_role": self.role, "login_enabled": enabled}

    def inspect(self, *, guard):
        """Point-in-time observation; never enable login or terminate sessions."""
        if self.binding.role not in {
            "shared_workload",
            "dedicated_workload",
        } or self.binding.database_name.startswith("sky_pool_"):
            raise ValueError("Only workload database login may be inspected")
        guard()
        with self.connect() as db:
            db.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            db.execute("SET LOCAL statement_timeout='10s'")
            self._verify_ownership(db)
            login = db.execute("SELECT rolcanlogin FROM pg_roles WHERE rolname=%s", (self.role,)).fetchone()
            db.execute("SELECT pg_stat_clear_snapshot()")
            sessions = db.execute(
                "SELECT count(*) FROM pg_stat_activity WHERE datname=%s AND usename=%s",
                (self.binding.database_name, self.role),
            ).fetchone()[0]
            if not login or type(login[0]) is not bool or type(sessions) is not int or sessions < 0:
                raise ValueError("Database restriction observation is incomplete")
            if db.execute("SHOW transaction_read_only").fetchone() != ("on",):
                raise ValueError("Read-only database transaction required")
            guard()
        guard()
        return {
            "binding": asdict(self.binding),
            "login_enabled": login[0],
            "active_sessions": sessions,
            "read_only": True,
        }
