"""Separate one-shot recovery consent and atomic new-source publication."""

from copy import deepcopy
from datetime import datetime
from uuid import uuid4

from application.security_hold import validate_release_request
from ports.remote_builds import digest
from ports.state import RecordConflict, StoredRecord

CONTROLS = (
    "security_hold",
    "security_execution_fence",
    "security_runtime_containment",
    "security_runtime_retirement",
    "security_database_restriction",
    "security_credential_preparation",
    "security_database_verification",
    "security_secret_access_fence",
    "security_artifact_review",
    "security_artifact_review_history",
    "security_recovery",
    "security_recovery_source_review",
    "security_recovery_source_review_history",
)


class PostgresSourceRecovery:
    def __init__(self, builds, operations):
        self.builds, self.operations, self.records = builds, operations, builds.records

    def initialize(self):
        self.builds.initialize()
        self.operations.initialize()
        with self.records._connection() as db:
            db.execute("SELECT pg_advisory_xact_lock(%s)", (self.records.MIGRATION_LOCK,))
            db.execute("""CREATE TABLE IF NOT EXISTS sky_state.source_recovery_executions(
                workspace text NOT NULL, approval_id text NOT NULL, recovery_id text NOT NULL,
                document jsonb NOT NULL, revision bigint NOT NULL DEFAULT 1,
                PRIMARY KEY(workspace,approval_id), UNIQUE(workspace,recovery_id),
                FOREIGN KEY(workspace,approval_id) REFERENCES sky_state.source_build_approvals(workspace,id))""")

    def load(self, actor, approval_id):
        self.builds.approvals.load(actor, approval_id)
        with self.records._connection() as db:
            row = db.execute(
                "SELECT document,revision FROM sky_state.source_recovery_executions WHERE workspace=%s AND approval_id=%s",
                (self.records.workspace, approval_id),
            ).fetchone()
        return StoredRecord(deepcopy(row[0]), "unused", row[1]) if row else None

    def _scope(self, db, actor, approval, snapshot, build):
        o = self.operations
        o._application_lock(db, approval["application_id"])
        now = self.builds._scope(db, actor, approval, snapshot)
        row = db.execute(
            "SELECT document,revision FROM sky_state.source_build_executions WHERE workspace=%s AND approval_id=%s FOR UPDATE",
            (self.records.workspace, approval["id"]),
        ).fetchone()
        if row != (build.record, build.revision) or build.record.get("phase") != "verified":
            raise RecordConflict("Recovery requires the exact verified new source build")
        fence = db.execute(
            "SELECT organization_id,job_id,incident_id,boundary_id FROM sky_state.incident_execution_fences WHERE workspace=%s AND application_id=%s",
            (o.workspace, approval["application_id"]),
        ).fetchone()
        if fence != (
            actor.organization_id,
            approval["job_id"],
            approval["incident_id"],
            approval["boundary_id"],
        ):
            raise ValueError("Current app execution barrier required")
        if db.execute(
            "SELECT id FROM sky_state.operations WHERE workspace=%s AND application_id=%s AND external_pending LIMIT 1",
            (o.workspace, approval["application_id"]),
        ).fetchone():
            raise ValueError("Old provider effects require reconciliation before recovery")
        return now

    def approve(self, actor, approval, snapshot, build, value):
        from psycopg.types.json import Jsonb

        validate_release_request(
            approval["incident_id"],
            value["review_ref"],
            snapshot.revision,
            approval["boundary_id"],
            value["approved_at"],
        )
        if (
            value["phase"] != "approved"
            or value["approval_id"] != approval["id"]
            or value["build_digest"] != digest(build.record)
            or value["plan_digest"] != digest(value["plan"])
            or value["plan"]["image"] != build.record["result"]["image"]
        ):
            raise ValueError("Exact distinct recovery consent required")
        with self.records._connection() as db:
            now = self._scope(db, actor, approval, snapshot, build)
            if (
                not datetime.fromisoformat(value["approved_at"])
                <= now
                < datetime.fromisoformat(value["expires_at"])
            ):
                raise ValueError("Fresh recovery consent required")
            self.builds.approvals._actor(actor)
            row = db.execute(
                """INSERT INTO sky_state.source_recovery_executions(workspace,approval_id,recovery_id,document)
                VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING revision""",
                (self.records.workspace, approval["id"], value["recovery_id"], Jsonb(value)),
            ).fetchone()
            if row is None:
                raise RecordConflict("Recovery consent already exists; inspect instead of replay")
        return StoredRecord(deepcopy(value), "unused", row[0])

    def transition(self, actor, approval, snapshot, build, current, phase, *, result=None):
        from psycopg.types.json import Jsonb

        old = current.record
        if (
            old["plan_digest"] != digest(old["plan"])
            or old["build_digest"] != digest(build.record)
            or phase
            not in {
                "approved": {"running"},
                "running": {"verified", "needs_attention"},
                "verified": {"verified", "needs_attention"},
            }.get(old["phase"], set())
        ):
            raise ValueError("Recovery cannot replay a consumed consent")
        if phase == "verified" and (
            not isinstance(result, dict)
            or result.get("image") != old["plan"]["image"]
            or result.get("verification", {}).get("http") != "verified"
            or result.get("verification", {}).get("image") != "verified"
            or (
                old["profile"] == "postgresql"
                and result.get("verification", {}).get("database_authentication") != "verified"
            )
        ):
            raise ValueError("Actual approved image, HTTP and applicable DB verification required")
        value = {
            **old,
            "phase": phase,
            "result": deepcopy(result if phase == "verified" else old.get("result")),
        }
        with self.records._connection() as db:
            now = self._scope(db, actor, approval, snapshot, build)
            if phase != "needs_attention" and now >= datetime.fromisoformat(old["expires_at"]):
                raise ValueError("Recovery consent expired")
            self.builds.approvals._actor(actor)
            row = db.execute(
                """UPDATE sky_state.source_recovery_executions SET document=%s,revision=revision+1
                WHERE workspace=%s AND approval_id=%s AND revision=%s AND document=%s RETURNING revision""",
                (Jsonb(value), self.records.workspace, approval["id"], current.revision, Jsonb(old)),
            ).fetchone()
            if row is None:
                raise RecordConflict("Recovery state changed; inspect commit outcome")
        return StoredRecord(value, "unused", row[0])

    def complete(self, actor, approval, snapshot, build, current):
        from psycopg.types.json import Jsonb

        value = current.record
        if (
            value.get("phase") != "verified"
            or value["plan_digest"] != digest(value["plan"])
            or value["build_digest"] != digest(build.record)
        ):
            raise ValueError("Exact verified source recovery required")
        with self.records._connection() as db:
            now = self._scope(db, actor, approval, snapshot, build)
            persisted = db.execute(
                "SELECT document,revision FROM sky_state.source_recovery_executions WHERE workspace=%s AND approval_id=%s FOR UPDATE",
                (self.records.workspace, approval["id"]),
            ).fetchone()
            if persisted != (value, current.revision) or now >= datetime.fromisoformat(value["expires_at"]):
                raise RecordConflict("Recovery completion changed or expired")
            history = snapshot.record.get("security_incident_history", [])
            if not isinstance(history, list) or len(history) >= 10:
                raise ValueError("Archive incident history before another recovery")
            boundary = {"id": uuid4().hex, "recorded_at": now.isoformat()}
            audit = {
                "id": value["recovery_id"],
                "incident_id": approval["incident_id"],
                "prior_boundary": approval["boundary_id"],
                "new_boundary": boundary,
                "recovered_at": now.isoformat(),
                "recovered_by": actor.user_id,
                "prior_result": deepcopy(snapshot.record.get("result")),
                "prior_source_ref": deepcopy(snapshot.record.get("source_ref")),
                "prior_source_digest": snapshot.record.get("source_digest"),
                "kind": "source_recovery",
                "profile": value["profile"],
                "source_build_approval_id": approval["id"],
                "source_build_id": approval["build_id"],
                "controls": {k: deepcopy(snapshot.record.get(k)) for k in CONTROLS},
            }
            audit["controls"]["security_source_recovery"] = deepcopy(value)
            request = build.record["request"]
            import json

            updated = {
                **snapshot.record,
                **dict.fromkeys(CONTROLS),
                "source_ref": deepcopy(request["source_ref"]),
                "source_digest": request["source_digest"],
                "plan": json.loads(request["approved_plan_json"]),
                "plan_digest": request["plan_digest"],
                "build_result": deepcopy(build.record["result"]),
                "recovery_build_approval_id": approval["id"],
                "operation_id": None,
                "approval_id": None,
                "result": deepcopy(value["result"]),
                "effective_backend": value["result"]["target"],
                "promotion_automation_consent": None,
                "security_review_boundary": boundary,
                "security_incident_history": history + [audit],
                "status": "succeeded",
                "deployment_state": "active",
            }
            o = self.operations
            rows = db.execute(
                "SELECT id FROM sky_state.operations WHERE workspace=%s AND application_id=%s AND status IN ('queued','running','needs_attention') FOR UPDATE",
                (o.workspace, approval["application_id"]),
            ).fetchall()
            for row in rows:
                db.execute(
                    "UPDATE sky_state.operations SET status='failed',lease_owner=NULL,lease_until=NULL,attempt_id=%s,lease_epoch=lease_epoch+1,row_version=row_version+1 WHERE workspace=%s AND id=%s",
                    (str(uuid4()), o.workspace, row[0]),
                )
                o._event(db, str(row[0]), "source_recovery_replaced")
            db.execute(
                "DELETE FROM sky_state.mutation_scopes WHERE workspace=%s AND application_id=%s",
                (o.workspace, approval["application_id"]),
            )
            db.execute(
                "UPDATE sky_state.metadata_records SET document=%s,revision=revision+1,modified_at=clock_timestamp() WHERE workspace=%s AND kind='job' AND record_id=%s AND revision=%s",
                (Jsonb(updated), o.workspace, approval["job_id"], snapshot.revision),
            )
            self.builds.approvals._actor(actor)
            completed = {
                **value,
                "phase": "recovered",
                "new_boundary": boundary,
                "completed_metadata_revision": snapshot.revision + 1,
            }
            db.execute(
                "UPDATE sky_state.source_recovery_executions SET document=%s,revision=revision+1 WHERE workspace=%s AND approval_id=%s",
                (Jsonb(completed), o.workspace, approval["id"]),
            )
            db.execute(
                "DELETE FROM sky_state.incident_execution_fences WHERE workspace=%s AND application_id=%s",
                (o.workspace, approval["application_id"]),
            )
        return StoredRecord(completed, "unused", current.revision + 1)
