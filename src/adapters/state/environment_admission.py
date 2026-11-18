"""Atomic consumption of preservation review/gate into one environment job.

This adapter has no public route and no dispatcher. It records a queued
operation only after locking the current owner, approved review and exact G7
record in the same PostgreSQL transaction. Workers still have to reload current
membership, registration and resource ownership before any external effect.
"""

import hashlib
import json
from dataclasses import asdict

from adapters.state.database_migration_reviews import PostgresMigrationReviews
from adapters.state.environment_gates import PostgresPreservationGates
from adapters.state.environment_reviews import PostgresEnvironmentReviews
from application.environment_admission import (
    RegisteredEnvironmentExecution,
    environment_execution_command,
    require_current_execution_gate,
    validate_environment_execution_operation,
)
from application.environment_gate_review import validate_preservation_gate_record
from domain.environment_transition import BASELINE_CAPABILITIES
from engine.environment_transition import validate_environment_transition_report
from ports.operations import IdempotencyConflict


class PostgresEnvironmentExecutionAdmission:
    def __init__(self, admission, *, current_principal):
        if not callable(current_principal):
            raise TypeError("Current environment admission membership resolver required")
        self.admission, self.operations = admission, admission.operations
        self.authorizer = PostgresMigrationReviews(admission)
        self.current_principal = current_principal

    def initialize(self):
        """Explicit additive migration; service startup must not call this."""
        PostgresEnvironmentReviews(self.admission).initialize()
        PostgresPreservationGates(self.admission, current_principal=self.current_principal).initialize()
        with self.operations.records._connection() as db:
            db.execute("SELECT pg_advisory_xact_lock(%s)", (self.operations.records.MIGRATION_LOCK,))
            db.execute("""CREATE TABLE IF NOT EXISTS sky_state.environment_execution_admission_versions (
                version integer PRIMARY KEY,applied_at timestamptz NOT NULL DEFAULT clock_timestamp())""")
            versions = db.execute(
                "SELECT version FROM sky_state.environment_execution_admission_versions ORDER BY version"
            ).fetchall()
            if versions not in ([], [(1,)]):
                raise ValueError("Unsupported environment execution admission schema")
            if versions:
                return
            db.execute("""CREATE TABLE sky_state.environment_execution_admissions (
                workspace text NOT NULL,admission_key text NOT NULL,request_fingerprint text NOT NULL,
                application_id text NOT NULL,organization_id text NOT NULL,created_by text NOT NULL,
                registration_id text NOT NULL,execution_revision text NOT NULL,
                review_id uuid NOT NULL,gate_record_id text NOT NULL,operation_id uuid NOT NULL,
                created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
                PRIMARY KEY(workspace,admission_key),
                UNIQUE(workspace,registration_id,execution_revision,gate_record_id),
                UNIQUE(workspace,operation_id),
                FOREIGN KEY(workspace,review_id) REFERENCES sky_state.environment_reviews(workspace,id),
                FOREIGN KEY(workspace,application_id,operation_id)
                    REFERENCES sky_state.operations(workspace,application_id,id))""")
            db.execute("INSERT INTO sky_state.environment_execution_admission_versions(version) VALUES(1)")

    def check_ready(self):
        with self.operations.records._connection() as db:
            if db.execute(
                "SELECT version FROM sky_state.environment_execution_admission_versions ORDER BY version"
            ).fetchall() != [(1,)]:
                raise ValueError("Environment execution admission requires explicit migration")
            db.execute(
                "SELECT admission_key,request_fingerprint,operation_id FROM sky_state.environment_execution_admissions LIMIT 0"
            )

    def _live(self, principal, execution):
        self.authorizer._authorize(principal)
        if not isinstance(execution, RegisteredEnvironmentExecution):
            raise TypeError("Registered environment execution required")
        if execution.job.owner.organization_id != principal.organization_id:
            raise FileNotFoundError("Environment execution not found")
        if self.current_principal(principal) != principal:
            raise PermissionError("Environment execution membership changed")

    @staticmethod
    def _digest(value):
        return hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()

    def submit(
        self,
        principal,
        execution,
        *,
        review_id,
        report_id,
        gate_record_id,
        request_key,
        confirm_write_pause,
        confirm_websocket_reconnect,
    ):
        self._live(principal, execution)
        request_key = self.operations._text(request_key, "request key")
        review_id = self.operations._uuid(review_id)
        command = environment_execution_command(
            principal,
            execution,
            review_id=review_id,
            report_id=report_id,
            gate_record_id=gate_record_id,
            request_key=request_key,
            confirm_write_pause=confirm_write_pause,
            confirm_websocket_reconnect=confirm_websocket_reconnect,
        )
        admission_key = self._digest(
            [self.operations.workspace, principal.organization_id, principal.user_id, request_key]
        )
        fingerprint = self._digest(command)
        job = execution.job
        with self.operations.records._connection() as db:
            self.authorizer._owner(db, principal, job.transfer.source.application_id)
            if self.current_principal(principal) != principal:
                raise PermissionError("Environment execution membership changed")
            previous = db.execute(
                """SELECT request_fingerprint,application_id,organization_id,created_by,
                registration_id,execution_revision,review_id::text,gate_record_id,operation_id::text
                FROM sky_state.environment_execution_admissions
                WHERE workspace=%s AND admission_key=%s FOR UPDATE""",
                (self.operations.workspace, admission_key),
            ).fetchone()
            immutable = (
                fingerprint,
                job.transfer.source.application_id,
                principal.organization_id,
                principal.user_id,
                job.id,
                execution.revision,
                review_id,
                gate_record_id,
            )
            if previous is not None:
                if previous[:-1] != immutable:
                    raise IdempotencyConflict(
                        "Environment request key belongs to a different reviewed execution"
                    )
                operation = self.operations._select(db, str(previous[-1]))
            else:
                now = db.execute("SELECT clock_timestamp()").fetchone()[0]
                if now >= job.expires_at:
                    raise ValueError("Environment execution registration expired")
                self._require_review(
                    db,
                    principal,
                    execution,
                    review_id=review_id,
                    report_id=report_id,
                    now=now,
                )
                self._require_gate(
                    db,
                    principal,
                    execution,
                    gate_record_id=gate_record_id,
                    now=now,
                )
                consumed = db.execute(
                    """SELECT admission_key FROM sky_state.environment_execution_admissions
                    WHERE workspace=%s AND registration_id=%s AND execution_revision=%s
                    AND gate_record_id=%s FOR UPDATE""",
                    (self.operations.workspace, job.id, execution.revision, gate_record_id),
                ).fetchone()
                if consumed is not None:
                    raise IdempotencyConflict(
                        "Environment execution gate was consumed by a different request"
                    )
                operation = self.operations._admit_in_transaction(
                    db,
                    job.transfer.source.application_id,
                    "environment_transfer",
                    "environment:" + admission_key,
                    command,
                )
                db.execute(
                    """INSERT INTO sky_state.environment_execution_admissions
                    (workspace,admission_key,request_fingerprint,application_id,organization_id,
                    created_by,registration_id,execution_revision,review_id,gate_record_id,operation_id)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        self.operations.workspace,
                        admission_key,
                        fingerprint,
                        job.transfer.source.application_id,
                        principal.organization_id,
                        principal.user_id,
                        job.id,
                        execution.revision,
                        review_id,
                        gate_record_id,
                        operation.id,
                    ),
                )
        self._live(principal, execution)
        return operation

    def revalidate(self, principal, execution, operation):
        """Reload every mutable authority before a registered worker effect."""
        self._live(principal, execution)
        command = validate_environment_execution_operation(operation, execution)
        with self.operations.records._connection() as db:
            self.authorizer._owner(db, principal, execution.job.transfer.source.application_id)
            if self.current_principal(principal) != principal:
                raise PermissionError("Environment execution membership changed")
            stored = self.operations._select(db, operation.id, lock=False)
            if (
                stored.attempt_id != operation.attempt_id
                or stored.application_id != operation.application_id
                or stored.kind != "environment_transfer"
                or stored.status not in {"queued", "running"}
                or stored.command != command
            ):
                raise ValueError("Durable environment operation changed")
            row = db.execute(
                """SELECT application_id,organization_id,created_by,registration_id,
                execution_revision,review_id::text,gate_record_id,operation_id::text
                FROM sky_state.environment_execution_admissions
                WHERE workspace=%s AND operation_id=%s FOR SHARE""",
                (self.operations.workspace, operation.id),
            ).fetchone()
            if row != (
                operation.application_id,
                principal.organization_id,
                principal.user_id,
                execution.job.id,
                execution.revision,
                command["review_id"],
                command["gate_record_id"],
                operation.id,
            ):
                raise ValueError("Environment execution admission binding changed")
            now = db.execute("SELECT clock_timestamp()").fetchone()[0]
            if now >= execution.job.expires_at:
                raise ValueError("Environment execution registration expired")
            self._require_review(
                db,
                principal,
                execution,
                review_id=command["review_id"],
                report_id=command["report_id"],
                now=now,
            )
            self._require_gate(
                db,
                principal,
                execution,
                gate_record_id=command["gate_record_id"],
                now=now,
            )
        self._live(principal, execution)
        return True

    def _require_review(self, db, principal, execution, *, review_id, report_id, now):
        row = db.execute(
            """SELECT r.application_id,r.organization_id,r.registration_id,r.report_id,
            r.document,r.expires_at,r.approved_by,r.revoked_at,h.review_id=r.id
            FROM sky_state.environment_reviews r JOIN sky_state.environment_review_heads h
            ON h.workspace=r.workspace AND h.application_id=r.application_id
            AND h.registration_id=r.registration_id
            WHERE r.workspace=%s AND r.id=%s FOR UPDATE OF r""",
            (self.operations.workspace, review_id),
        ).fetchone()
        if row is None or row[1] != principal.organization_id:
            raise FileNotFoundError("Environment preservation review not found")
        document = validate_environment_transition_report(row[4])
        policy_document = execution.policy.document()
        # The approved equivalence review covers the stable preservation
        # outcomes. Phase obligations such as rehearsal/current approval/post-
        # cutover validation live in the staged gate ledger and must not be
        # fabricated as already-complete review criteria.
        expected_requirements = [
            value for value in policy_document["requirements"] if value["capability"] in BASELINE_CAPABILITIES
        ]
        if (
            row[0] != execution.job.transfer.source.application_id
            or row[2] != execution.review_registration_id
            or row[3] != report_id
            or row[5] <= now
            or row[6] is None
            or row[7] is not None
            or row[8] is not True
            or document["status"] != "verified"
            or document["scope"] != asdict(execution.policy.scope)
            or document["requirements"] != expected_requirements
        ):
            raise ValueError("Environment preservation review is not current and approved")

    def _require_gate(self, db, principal, execution, *, gate_record_id, now):
        policy_document = execution.policy.document()
        row = db.execute(
            """SELECT document,policy_document,application_id,organization_id
            FROM sky_state.environment_gate_records WHERE workspace=%s AND registration_id=%s
            AND policy_id=%s ORDER BY sequence DESC LIMIT 1 FOR UPDATE""",
            (
                self.operations.workspace,
                execution.review_registration_id,
                policy_document["policy_id"],
            ),
        ).fetchone()
        if row is None:
            raise FileNotFoundError("Environment execution gate not found")
        if row[1:] != (
            policy_document,
            execution.job.transfer.source.application_id,
            principal.organization_id,
        ):
            raise ValueError("Environment execution gate scope changed")
        document = validate_preservation_gate_record(execution.policy, row[0])
        require_current_execution_gate(execution, document, now=now, expected_record_id=gate_record_id)
