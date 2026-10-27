"""Commit verified recovery and invalidate old worker attempts under the app barrier.

This is internal composition, not an HTTP arbitrary-patch or receipt endpoint.
No provider mutation is issued here; commit uncertainty must be inspected.
"""

from copy import deepcopy
from datetime import UTC, datetime
from uuid import uuid4

from adapters.state.incident_execution import PostgresIncidentExecutionControl
from application.incident_recovery import FIELD
from ports.state import RecordConflict

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
    FIELD,
)


class PostgresIncidentRecoveryCompletion(PostgresIncidentExecutionControl):
    def complete_recovery(
        self, principal, job_id, *, incident_id, expected_boundary, expected_revision, recovery_id
    ):
        from application.security_hold import validate_release_request

        now = datetime.now(UTC).isoformat()
        validate_release_request(
            incident_id, "recovery-completion", expected_revision, expected_boundary, now
        )
        app = self._scope(principal, job_id)
        o = self.operations
        with o.records._connection() as db:
            o._application_lock(db, app)
            snapshot = self._current(
                db, principal, job_id, incident_id, expected_boundary, expected_revision, lock=True
            )
            recovery = snapshot.record.get(FIELD)
            if snapshot.record.get("security_recovery_source_review") is not None:
                raise ValueError("New-source review cannot be completed by unchanged-image recovery")
            if (
                not isinstance(recovery, dict)
                or recovery.get("phase") != "verified"
                or recovery.get("id") != recovery_id
                or recovery.get("external_pending") is not False
                or not isinstance(recovery.get("result"), dict)
            ):
                raise ValueError("Exact verified single-use recovery result required")
            if (recovery.get("incident_id"), recovery.get("boundary_id")) != (
                incident_id,
                expected_boundary,
            ) or datetime.fromisoformat(recovery["expires_at"]) <= datetime.fromisoformat(now):
                raise ValueError("Recovery approval expired or changed before completion")
            fenced = db.execute(
                "SELECT organization_id,job_id,incident_id,boundary_id FROM sky_state.incident_execution_fences WHERE workspace=%s AND application_id=%s",
                (o.workspace, app),
            ).fetchone()
            if fenced != (principal.organization_id, job_id, incident_id, expected_boundary):
                raise ValueError("Exact app execution barrier required for recovery completion")
            pending = db.execute(
                "SELECT id FROM sky_state.operations WHERE workspace=%s AND application_id=%s AND external_pending LIMIT 1",
                (o.workspace, app),
            ).fetchone()
            if pending:
                raise ValueError("Provider requests still require reconciliation")
            result = recovery["result"]
            if (
                result.get("image") != recovery["plan"]["image"]
                or result.get("verification", {}).get("http") != "verified"
                or result.get("verification", {}).get("database_authentication") != "verified"
            ):
                raise ValueError("Verified approved runtime result required")
            history = snapshot.record.get("security_incident_history", [])
            if not isinstance(history, list) or len(history) >= 10:
                raise ValueError("Archive security incident history before another recovery")
            boundary = {"id": uuid4().hex, "recorded_at": now}
            audit = {
                "id": recovery_id,
                "incident_id": incident_id,
                "prior_boundary": expected_boundary,
                "new_boundary": boundary,
                "recovered_at": now,
                "recovered_by": principal.user_id,
                "prior_result": deepcopy(snapshot.record.get("result")),
                "controls": {k: deepcopy(snapshot.record.get(k)) for k in CONTROLS},
            }
            updated = {
                **snapshot.record,
                **dict.fromkeys(CONTROLS),
                "security_incident_history": history + [audit],
                "security_artifact_review_history": [],
                "security_review_boundary": boundary,
                "result": deepcopy(result),
                "effective_backend": result["target"],
                "promotion_automation_consent": None,
                "status": "succeeded",
                "deployment_state": "active",
            }
            old = db.execute(
                "SELECT id,attempt_id,status,lease_epoch,row_version FROM sky_state.operations WHERE workspace=%s AND application_id=%s AND status IN ('queued','running','needs_attention') FOR UPDATE",
                (o.workspace, app),
            ).fetchall()
            audit["invalidated_operations"] = [
                {
                    "id": str(row[0]),
                    "attempt_id": str(row[1]),
                    "status": row[2],
                    "lease_epoch": row[3],
                    "row_version": row[4],
                }
                for row in old
            ]
            for operation_id, *_ in old:
                db.execute(
                    """UPDATE sky_state.operations SET status='failed',lease_owner=NULL,lease_until=NULL,
                    attempt_id=%s,lease_epoch=lease_epoch+1,row_version=row_version+1,result=%s
                    WHERE workspace=%s AND id=%s""",
                    (
                        str(uuid4()),
                        o._json({"failure_code": "incident_execution_replaced", "recovery_id": recovery_id}),
                        o.workspace,
                        operation_id,
                    ),
                )
                o._event(db, operation_id, "incident_execution_replaced")
            db.execute(
                "DELETE FROM sky_state.mutation_scopes WHERE workspace=%s AND application_id=%s",
                (o.workspace, app),
            )
            row = db.execute(
                "UPDATE sky_state.metadata_records SET document=%s,revision=revision+1,modified_at=clock_timestamp() WHERE workspace=%s AND kind='job' AND record_id=%s AND revision=%s RETURNING revision",
                (o._json(updated), o.workspace, job_id, expected_revision),
            ).fetchone()
            if row is None:
                raise RecordConflict("Recovery metadata changed before commit")
            if self.revalidate() != principal:
                raise PermissionError("Administrator membership changed before recovery commit")
            db.execute(
                "DELETE FROM sky_state.incident_execution_fences WHERE workspace=%s AND application_id=%s",
                (o.workspace, app),
            )
        return {
            "recovery_id": recovery_id,
            "phase": "recovered",
            "metadata_revision": row[0],
            "hold_released": True,
            "automation_reenabled": False,
            "old_worker_attempts_invalidated": True,
            "result": deepcopy(result),
        }
