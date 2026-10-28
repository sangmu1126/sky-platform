"""Read-preserving fence for a bounded, administrator-owned table profile.

This is a planned-migration controller, never incident containment. The caller
must close the registered HTTP writer gate first. No application-owned schema,
column grants, PUBLIC writes, role inheritance or custom routines are adopted.
"""

from dataclasses import asdict

from psycopg import sql

from adapters.database.promotion_copy import _inventory
from adapters.database.promotion_fence import PostgresApplicationFence
from ports.database_promotion import ReadPreservingWriteFence


class PostgresPromotionWriteFence(PostgresApplicationFence, ReadPreservingWriteFence):
    def set_writes(self, enabled, *, guard):
        if type(enabled) is not bool or self.administrative_database != self.binding.database_name:
            raise ValueError("Explicit workload-local write fence required")
        if self.binding.role not in {"shared_workload", "dedicated_workload"}:
            raise ValueError("Only workload writes may be fenced")
        guard()
        with self.connect() as db:
            db.execute("SET LOCAL lock_timeout='5s'")
            db.execute("SET LOCAL statement_timeout='30s'")
            self._verify_ownership(db)
            if db.execute(
                "SELECT rolcanlogin,rolinherit FROM pg_roles WHERE rolname=%s", (self.role,)
            ).fetchone() != (True, False):
                raise ValueError("Existing restricted LOGIN NOINHERIT role required")
            if db.execute(
                "SELECT has_database_privilege(%s,current_database(),'CONNECT'),"
                "has_database_privilege(%s,current_database(),'CREATE'),"
                "has_schema_privilege(%s,'public','USAGE'),"
                "has_schema_privilege(%s,'public','CREATE')",
                (self.role,) * 4,
            ).fetchone() != (True, False, True, False):
                raise ValueError("Read-only schema access and administrator-owned database required")
            tables = _inventory(db)
            if not tables or len(tables) > 100:
                raise ValueError("Bounded supported tables required")
            names = sql.SQL(",").join(sql.Identifier("public", name) for name, _, _ in tables)
            # Drain old writers and DDL, but allow ordinary SELECT, including
            # pooled connections, throughout this transaction. Timeout rolls back.
            db.execute(sql.SQL("LOCK TABLE {} IN EXCLUSIVE MODE").format(names))
            if _inventory(db) != tables:
                raise ValueError("Schema changed during write fence")
            if db.execute(
                """SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='public' AND (pg_has_role(%s,c.relowner,'USAGE') OR EXISTS(
                    SELECT 1 FROM aclexplode(c.relacl) a WHERE a.grantee=0 AND
                    a.privilege_type NOT IN ('SELECT')))) OR EXISTS(
                    SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
                    JOIN pg_namespace n ON n.oid=c.relnamespace
                    WHERE n.nspname='public' AND a.attacl IS NOT NULL)""",
                (self.role,),
            ).fetchone()[0]:
                raise ValueError("Application ownership, PUBLIC or column grants cannot be fenced")
            for name, _, _ in tables:
                relation = sql.Identifier("public", name)
                if db.execute(
                    "SELECT has_table_privilege(%s,%s,'SELECT')", (self.role, relation.as_string(db))
                ).fetchone() != (True,):
                    raise ValueError("Application SELECT must remain available")
                # Never grant TRUNCATE, REFERENCES, TRIGGER or MAINTAIN. The
                # approved execution profile is exactly table DML plus SELECT.
                db.execute(
                    sql.SQL("REVOKE ALL PRIVILEGES ON {} FROM {}").format(relation, sql.Identifier(self.role))
                )
                db.execute(sql.SQL("GRANT SELECT ON {} TO {}").format(relation, sql.Identifier(self.role)))
                if enabled:
                    db.execute(
                        sql.SQL("GRANT INSERT,UPDATE,DELETE ON {} TO {}").format(
                            relation, sql.Identifier(self.role)
                        )
                    )
            # Identity INSERT does not require USAGE. For this profile arbitrary
            # sequence manipulation is prohibited even while writes are enabled.
            db.execute(
                sql.SQL("REVOKE USAGE,UPDATE ON ALL SEQUENCES IN SCHEMA public FROM {}").format(
                    sql.Identifier(self.role)
                )
            )
            for name, _, _ in tables:
                privileges = db.execute(
                    "SELECT has_table_privilege(%s,%s,'INSERT'),has_table_privilege(%s,%s,'UPDATE'),"
                    "has_table_privilege(%s,%s,'DELETE'),has_table_privilege(%s,%s,'TRUNCATE'),"
                    "has_table_privilege(%s,%s,'TRIGGER'),has_table_privilege(%s,%s,'REFERENCES')",
                    (self.role, sql.Identifier("public", name).as_string(db)) * 6,
                ).fetchone()
                if privileges != (enabled, enabled, enabled, False, False, False):
                    raise ValueError("Application write privileges differ from registered profile")
            guard()
        guard()
        return {
            "binding": asdict(self.binding),
            "login_enabled": True,
            "writes_enabled": enabled,
            "reads_preserved": True,
            "verified_scope": "owned_table_acl_write_fence",
        }
