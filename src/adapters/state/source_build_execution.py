"""Single-use source build reservations independent of ordinary deployment queues."""

from copy import deepcopy
from datetime import datetime, timedelta

from ports.remote_builds import digest, validate_request, validate_result
from ports.source_build_approvals import validate_source_build_approval
from ports.state import RecordConflict, StoredRecord


class PostgresSourceBuildExecutions:
    def __init__(self, approvals):
        self.approvals, self.records = approvals, approvals.records

    def initialize(self):
        self.approvals.initialize()
        with self.records._connection() as db:
            db.execute("SELECT pg_advisory_xact_lock(%s)", (self.records.MIGRATION_LOCK,))
            db.execute(
                "CREATE TABLE IF NOT EXISTS sky_state.source_build_execution_schema_versions(version integer PRIMARY KEY CHECK(version=1))"
            )
            versions = tuple(
                row[0]
                for row in db.execute(
                    "SELECT version FROM sky_state.source_build_execution_schema_versions ORDER BY version"
                ).fetchall()
            )
            if versions not in ((), (1,)):
                raise ValueError("Unsupported source build execution schema")
            if not versions:
                db.execute("""CREATE TABLE sky_state.source_build_executions(
                    workspace text NOT NULL, approval_id text NOT NULL, document jsonb NOT NULL,
                    revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
                    PRIMARY KEY(workspace,approval_id),
                    FOREIGN KEY(workspace,approval_id) REFERENCES sky_state.source_build_approvals(workspace,id))""")
                db.execute("INSERT INTO sky_state.source_build_execution_schema_versions(version) VALUES(1)")

    def load(self, actor, approval_id):
        self.approvals.load(actor, approval_id)
        with self.records._connection() as db:
            row = db.execute(
                "SELECT document,revision FROM sky_state.source_build_executions WHERE workspace=%s AND approval_id=%s",
                (self.records.workspace, approval_id),
            ).fetchone()
        return StoredRecord(deepcopy(row[0]), "unused", row[1]) if row else None

    def _scope(self, db, actor, approval, snapshot, *, fresh=False):
        self.approvals._locked_job(db, actor, approval, snapshot)
        row = db.execute(
            "SELECT document FROM sky_state.source_build_approvals WHERE workspace=%s AND id=%s FOR UPDATE",
            (self.records.workspace, approval["id"]),
        ).fetchone()
        if row is None or row[0] != approval or approval["revoked_at"] is not None:
            raise RecordConflict("Source build consent changed or revoked")
        now = db.execute("SELECT clock_timestamp()").fetchone()[0]
        if (
            approval["job_digest"] != digest(snapshot.record)
            or approval["metadata_revision"] != snapshot.revision
            or approval["source_review_digest"]
            != digest(snapshot.record.get("security_recovery_source_review"))
            or (
                fresh
                and not datetime.fromisoformat(approval["approved_at"])
                <= now
                < datetime.fromisoformat(approval["expires_at"])
            )
        ):
            raise RecordConflict("Source build binding changed or expired")
        return now

    def reserve(self, actor, approval, snapshot, request):
        from psycopg.types.json import Jsonb

        a = validate_source_build_approval(approval)
        artifact, _ = validate_request(request)
        original = a["candidate"]
        if (
            request["workspace"] != self.records.workspace
            or request["build_id"] != a["build_id"]
            or request["job_id"] != a["job_id"]
            or request["created_by"] != a["approved_by"]
            or {**artifact.record(), "kind": "original"} != original
            or any(
                request[k] != a["builder"][k]
                for k in ["repository", "workflow_sha", "platform_code_sha", "bucket", "account_id", "region"]
            )
        ):
            raise ValueError("Exact unchanged reviewed tree and pinned builder required")
        with self.records._connection() as db:
            now = self._scope(db, actor, a, snapshot, fresh=True)
            value = {
                "version": 1,
                "approval_id": a["id"],
                "approval_digest": digest(a),
                "request": deepcopy(request),
                "request_digest": digest(request),
                "phase": "reserved",
                "started_at": now.isoformat(),
                "deadline": (now + timedelta(seconds=3600)).isoformat(),
                "run": None,
                "result": None,
                "image_receipt": None,
            }
            self.approvals._actor(actor)
            row = db.execute(
                """INSERT INTO sky_state.source_build_executions(workspace,approval_id,document)
                SELECT %s,%s,%s WHERE clock_timestamp()<%s ON CONFLICT DO NOTHING RETURNING revision""",
                (self.records.workspace, a["id"], Jsonb(value), datetime.fromisoformat(a["expires_at"])),
            ).fetchone()
            if row is None:
                raise RecordConflict("Build consent already consumed or expired; inspect, never redispatch")
        return StoredRecord(value, "unused", row[0])

    def transition(
        self, actor, approval, snapshot, current, phase, *, run=None, result=None, image_receipt=None
    ):
        from psycopg.types.json import Jsonb

        allowed = {
            "reserved": {"dispatching"},
            "dispatching": {"waiting", "verified", "failed"},
            "waiting": {"verified", "failed"},
        }
        old = current.record
        if phase not in allowed.get(old.get("phase"), set()):
            raise ValueError("Source build transition cannot replay dispatch")
        if (
            old.get("approval_id") != approval["id"]
            or old.get("approval_digest") != digest(approval)
            or digest(old.get("request")) != old.get("request_digest")
        ):
            raise ValueError("Build reservation binding changed")
        if phase in {"verified", "failed"}:
            if (
                not isinstance(run, dict)
                or set(run) != {"run_id", "succeeded"}
                or type(run["run_id"]) is not int
                or run["run_id"] < 1
                or type(run["succeeded"]) is not bool
            ):
                raise ValueError("Exact observed workflow required")
            if phase == "verified":
                validate_result(result, old["request"], run["run_id"])
                if (
                    not run["succeeded"]
                    or not isinstance(image_receipt, dict)
                    or image_receipt.get("manifest_bytes_verified") is not True
                    or image_receipt.get("image") != result["image"]
                ):
                    raise ValueError("Verified build result and native image receipt required")
            elif run["succeeded"] or result is not None or image_receipt is not None:
                raise ValueError("Exact failed workflow observation required")
        elif any(x is not None for x in (run, result, image_receipt)):
            raise ValueError("Build output cannot precede verified workflow")
        value = {
            **old,
            "phase": phase,
            "run": deepcopy(run),
            "result": deepcopy(result),
            "image_receipt": deepcopy(image_receipt),
        }
        with self.records._connection() as db:
            now = self._scope(db, actor, approval, snapshot)
            if now >= datetime.fromisoformat(old["deadline"]):
                raise ValueError("Build observation window expired")
            self.approvals._actor(actor)
            row = db.execute(
                """UPDATE sky_state.source_build_executions SET document=%s,revision=revision+1
                WHERE workspace=%s AND approval_id=%s AND revision=%s AND document=%s RETURNING revision""",
                (Jsonb(value), self.records.workspace, approval["id"], current.revision, Jsonb(old)),
            ).fetchone()
            if row is None:
                raise RecordConflict("Source build changed; inspect persisted outcome")
        return StoredRecord(value, "unused", row[0])
