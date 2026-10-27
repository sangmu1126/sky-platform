"""Independent build-consent ledger; never dispatch or mutate held job metadata."""

from copy import deepcopy
from datetime import datetime

from application.deployment_writes import authorize_job_snapshot
from application.incident_source_review import FIELD, IncidentSourceReview, parent_digest, validate_review
from application.security_hold import security_hold_projection
from domain.access import Principal, Role
from ports.remote_builds import digest
from ports.source_build_approvals import validate_source_build_approval
from ports.state import RecordConflict, StoredJob


class PostgresSourceBuildApprovals:
    def __init__(self, records, *, revalidate):
        self.records, self.revalidate = records, revalidate

    def initialize(self):
        """Explicit maintenance only. Runtime startup and approve never run DDL."""
        self.records.initialize()
        with self.records._connection() as db:
            db.execute("SELECT pg_advisory_xact_lock(%s)", (self.records.MIGRATION_LOCK,))
            db.execute(
                "CREATE TABLE IF NOT EXISTS sky_state.source_build_schema_versions (version integer PRIMARY KEY CHECK(version=1))"
            )
            versions = tuple(
                row[0]
                for row in db.execute(
                    "SELECT version FROM sky_state.source_build_schema_versions ORDER BY version"
                ).fetchall()
            )
            if versions not in ((), (1,)):
                raise ValueError("Unknown source build approval schema")
            if not versions:
                db.execute("""CREATE TABLE sky_state.source_build_approvals (
                    workspace text NOT NULL, id text NOT NULL,
                    job_id text NOT NULL, organization_id text NOT NULL, application_id text NOT NULL,
                    source_review_id text NOT NULL, build_id uuid NOT NULL,
                    document jsonb NOT NULL CHECK(jsonb_typeof(document)='object'),
                    PRIMARY KEY(workspace,id), UNIQUE(workspace,build_id),
                    UNIQUE(workspace,job_id,source_review_id))""")
                db.execute("INSERT INTO sky_state.source_build_schema_versions(version) VALUES(1)")

    def check_ready(self):
        """Read-only opt-in probe; no automatic DDL."""
        with self.records._connection() as db:
            db.execute("SET TRANSACTION READ ONLY")
            db.execute("SET LOCAL statement_timeout=3000")
            versions = tuple(
                row[0]
                for row in db.execute(
                    "SELECT version FROM sky_state.source_build_schema_versions ORDER BY version"
                ).fetchall()
            )
            if versions != (1,):
                raise ValueError("Source build consent schema requires explicit migration")
            db.execute(
                "SELECT workspace,id,job_id,organization_id,application_id,source_review_id,build_id,document FROM sky_state.source_build_approvals LIMIT 0"
            )

    def _actor(self, actor):
        if not isinstance(actor, Principal) or actor.role is not Role.ADMIN or self.revalidate() != actor:
            raise PermissionError("Current organization administrator required")

    def _locked_job(self, db, actor, approval, expected):
        self._actor(actor)
        row = db.execute(
            """SELECT document,modified_at,revision FROM sky_state.metadata_records
            WHERE workspace=%s AND kind='job' AND record_id=%s FOR UPDATE""",
            (self.records.workspace, approval["job_id"]),
        ).fetchone()
        if row is None:
            raise FileNotFoundError("Held deployment not found")
        current = authorize_job_snapshot(
            actor, approval["job_id"], StoredJob(row[0], row[1].isoformat(), row[2])
        )
        status = security_hold_projection(current.record, include_details=True)
        if current.revision != expected.revision or current.record != expected.record:
            raise RecordConflict("Held source changed before build consent write")
        if (
            status.get("record_valid") is not True
            or status["hold"]["incident_id"] != approval["incident_id"]
            or current.record.get("security_review_boundary")
            != {"id": approval["boundary_id"], "recorded_at": status["hold"]["recorded_at"]}
            or (current.record["organization_id"], current.record["application_id"])
            != (approval["organization_id"], approval["application_id"])
            or actor.organization_id != approval["organization_id"]
        ):
            raise ValueError("Exact held source build scope required")
        return current

    def create(self, actor, approval, snapshot):
        from psycopg.types.json import Jsonb

        a = deepcopy(validate_source_build_approval(approval))
        with self.records._connection() as db:
            current = self._locked_job(db, actor, a, snapshot)
            now = db.execute("SELECT clock_timestamp()").fetchone()[0]
            review = validate_review(current.record.get(FIELD))
            IncidentSourceReview._history(current.record, a["job_id"])
            if (
                review["revoked_at"] is not None
                or review["approved_metadata_revision"] != current.revision
                or parent_digest(current.record) != review["parent_digest"]
                or datetime.fromisoformat(a["expires_at"]) > datetime.fromisoformat(review["expires_at"])
                or not datetime.fromisoformat(review["approved_at"])
                <= now
                < datetime.fromisoformat(review["expires_at"])
                or a["approved_by"] != actor.user_id
                or a["revoked_at"] is not None
                or a["metadata_revision"] != current.revision
                or a["job_digest"] != digest(current.record)
                or a["source_review_digest"] != digest(current.record.get("security_recovery_source_review"))
                or a["source_review_id"]
                != current.record.get("security_recovery_source_review", {}).get("id")
                or a["candidate"]
                != current.record.get("security_recovery_source_review", {}).get("candidate")
                or not datetime.fromisoformat(a["approved_at"])
                <= now
                < datetime.fromisoformat(a["expires_at"])
            ):
                raise ValueError("Current unexpired source build consent required")
            self._actor(actor)
            row = db.execute(
                """INSERT INTO sky_state.source_build_approvals
                (workspace,id,job_id,organization_id,application_id,source_review_id,build_id,document)
                SELECT %s,%s,%s,%s,%s,%s,%s,%s WHERE clock_timestamp() < %s
                ON CONFLICT DO NOTHING RETURNING id""",
                (
                    self.records.workspace,
                    a["id"],
                    a["job_id"],
                    a["organization_id"],
                    a["application_id"],
                    a["source_review_id"],
                    a["build_id"],
                    Jsonb(a),
                    datetime.fromisoformat(a["expires_at"]),
                ),
            ).fetchone()
            if row is None:
                raise RecordConflict("Build consent identity or source review already used; inspect ledger")

    def load(self, actor, approval_id):
        self._actor(actor)
        if not isinstance(approval_id, str) or len(approval_id) != 32:
            raise ValueError("Exact build consent identity required")
        with self.records._connection() as db:
            row = db.execute(
                """SELECT document FROM sky_state.source_build_approvals
                WHERE workspace=%s AND id=%s AND organization_id=%s""",
                (self.records.workspace, approval_id, actor.organization_id),
            ).fetchone()
        if row is None:
            raise FileNotFoundError("Source build approval not found")
        result = deepcopy(validate_source_build_approval(row[0]))
        if result["id"] != approval_id or result["organization_id"] != actor.organization_id:
            raise ValueError("Source build approval ledger scope mismatch")
        self._actor(actor)
        return result

    def revoke(self, actor, approval, snapshot, *, now, review_ref):
        from psycopg.types.json import Jsonb

        a = deepcopy(validate_source_build_approval(approval))
        if a["revoked_at"] is not None:
            raise ValueError("Build consent already revoked; inspect ledger")
        updated = validate_source_build_approval(
            {**a, "revoked_at": now, "revoked_by": actor.user_id, "revocation_ref": review_ref}
        )
        with self.records._connection() as db:
            self._locked_job(db, actor, a, snapshot)
            self._actor(actor)
            row = db.execute(
                """UPDATE sky_state.source_build_approvals SET document=%s
                WHERE workspace=%s AND id=%s AND organization_id=%s AND document=%s RETURNING id""",
                (Jsonb(updated), self.records.workspace, a["id"], actor.organization_id, Jsonb(a)),
            ).fetchone()
            if row is None:
                raise RecordConflict("Build consent changed; inspect ledger")
        return deepcopy(updated)
