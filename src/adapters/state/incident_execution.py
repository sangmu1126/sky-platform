"""An app-wide PostgreSQL barrier sharing the worker external-intent lock.

A previously admitted provider call may still be in flight. Never clear its
pending marker, revoke an unrelated lease, or describe this as an AWS/IAM fence.
"""

from copy import deepcopy

from application.deployment_writes import authorize_job_snapshot
from application.security_hold import security_hold_projection
from domain.access import Role
from ports.state import RecordConflict, StoredJob


class PostgresIncidentExecutionControl:
    def __init__(self, operations, *, revalidate):
        self.operations, self.revalidate = operations, revalidate

    def _current(self, connection, principal, job_id, incident_id, boundary, revision, *, lock):
        if principal.role is not Role.ADMIN or self.revalidate() != principal:
            raise PermissionError("Current organization administrator required")
        row = connection.execute(
            """SELECT document,modified_at,revision FROM sky_state.metadata_records
            WHERE workspace=%s AND kind='job' AND record_id=%s"""
            + (" FOR UPDATE" if lock else ""),
            (self.operations.workspace, job_id),
        ).fetchone()
        if row is None:
            raise FileNotFoundError("Deployment not found")
        snapshot = authorize_job_snapshot(principal, job_id, StoredJob(row[0], row[1].isoformat(), row[2]))
        status = security_hold_projection(snapshot.record, include_details=True)
        if snapshot.revision != revision:
            raise RecordConflict("Deployment changed since incident execution review")
        if (
            status.get("record_valid") is not True
            or status["hold"]["incident_id"] != incident_id
            or snapshot.record.get("security_review_boundary")
            != {"id": boundary, "recorded_at": status["hold"]["recorded_at"]}
        ):
            raise ValueError("Exact current security hold and boundary required")
        return snapshot

    def _scope(self, principal, job_id, **options):
        # Resolve app before taking locks, then verify the locked metadata again.
        from application.deployment_writes import DeploymentMetadataWriter

        snapshot = DeploymentMetadataWriter(self.operations.records).snapshot(principal, job_id)
        app = snapshot.record.get("application_id")
        self.operations._text(app, "application identity")
        return app

    def _run(self, principal, job_id, *, incident_id, expected_boundary, expected_revision, mutate):
        from datetime import UTC, datetime

        from application.security_hold import validate_release_request

        validate_release_request(
            incident_id,
            "execution-fence",
            expected_revision,
            expected_boundary,
            datetime.now(UTC).isoformat(),
        )
        app = self._scope(principal, job_id)
        o = self.operations
        with o.records._connection() as db:
            o._application_lock(db, app)
            snapshot = self._current(
                db, principal, job_id, incident_id, expected_boundary, expected_revision, lock=mutate
            )
            if snapshot.record.get("application_id") != app:
                raise RecordConflict("Application changed during incident fence")
            expected = (principal.organization_id, job_id, incident_id, expected_boundary)
            row = db.execute(
                """SELECT organization_id,job_id,incident_id,boundary_id FROM sky_state.incident_execution_fences
                WHERE workspace=%s AND application_id=%s""",
                (o.workspace, app),
            ).fetchone()
            if row is not None and row != expected:
                raise ValueError("Application has a different incident execution barrier")
            changed = mutate and row is None
            if changed:
                db.execute(
                    """INSERT INTO sky_state.incident_execution_fences
                    (workspace,application_id,organization_id,job_id,incident_id,boundary_id,recorded_by)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                    (o.workspace, app, *expected, principal.user_id),
                )
                marker = {
                    "incident_id": incident_id,
                    "boundary_id": expected_boundary,
                    "scope": "sky_postgres_operations",
                }
                if snapshot.record.get("security_execution_fence") is not None:
                    raise ValueError("Existing execution barrier metadata requires inspection")
                db.execute(
                    """UPDATE sky_state.metadata_records SET document=%s,revision=revision+1,modified_at=clock_timestamp()
                    WHERE workspace=%s AND kind='job' AND record_id=%s AND revision=%s""",
                    (
                        o._json(
                            {
                                **snapshot.record,
                                "security_execution_fence": marker,
                                "promotion_automation_consent": None,
                            }
                        ),
                        o.workspace,
                        job_id,
                        snapshot.revision,
                    ),
                )
                row = expected
            if (
                row == expected
                and not changed
                and snapshot.record.get("security_execution_fence")
                != {
                    "incident_id": incident_id,
                    "boundary_id": expected_boundary,
                    "scope": "sky_postgres_operations",
                }
            ):
                raise ValueError("Execution barrier metadata is missing or changed")
            # Intent and barrier take the same app lock. Thus no new external
            # intent can slip past the snapshot after this transaction commits.
            pending = db.execute(
                """SELECT id FROM sky_state.operations WHERE workspace=%s AND application_id=%s
                AND external_pending ORDER BY id LIMIT 101""",
                (o.workspace, app),
            ).fetchall()
            if self.revalidate() != principal:
                raise PermissionError("Administrator membership changed")
            report = {
                "incident_id": incident_id,
                "boundary_id": expected_boundary,
                "metadata_revision": snapshot.revision + int(changed),
                "application_id": app,
                "sky_operation_admission_fenced": row == expected,
                "sky_worker_external_intents_fenced": row == expected,
                "pending_operation_ids": [str(item[0]) for item in pending[:100]],
                "pending_inventory_complete": len(pending) <= 100,
                "registered_operation_requests_settled": row == expected and not pending,
                "fence_scope": "sky_postgres_operations",
                "aws_scheduler_fenced": False,
                "execution_exclusion_verified": False,
                "recovery_authorized": False,
                "state_changed": changed,
                "read_only": not mutate,
            }
        return deepcopy(report)

    def fence(self, principal, job_id, **options):
        return self._run(principal, job_id, mutate=True, **options)

    def inspect(self, principal, job_id, **options):
        return self._run(principal, job_id, mutate=False, **options)
