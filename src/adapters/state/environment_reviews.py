"""Durable owner-bound preservation reviews. Approval never admits an executor.

Caller must supply reports from trusted registered collectors and recheck live
membership. Content hashes/recalculation do not authenticate uploaded reports.
Every observation keeps its original expiry; recording again cannot refresh it.
"""

from datetime import datetime, timedelta
from uuid import uuid4

from adapters.state.database_migration_reviews import PostgresMigrationReviews
from domain.environment_transition import _ref
from engine.environment_transition import validate_environment_transition_report
from ports.environment_transition import EnvironmentPreservationReview


class PostgresEnvironmentReviews:
    def __init__(self, admission):
        self.admission, self.operations = admission, admission.operations
        self.authorizer = PostgresMigrationReviews(admission)

    def initialize(self):
        self.admission.initialize()
        with self.operations.records._connection() as db:
            db.execute("SELECT pg_advisory_xact_lock(%s)", (self.operations.records.MIGRATION_LOCK,))
            db.execute("""CREATE TABLE IF NOT EXISTS sky_state.environment_review_versions (
                version integer PRIMARY KEY,applied_at timestamptz NOT NULL DEFAULT clock_timestamp())""")
            versions = tuple(
                r[0]
                for r in db.execute(
                    "SELECT version FROM sky_state.environment_review_versions ORDER BY version"
                ).fetchall()
            )
            if versions not in ((), (1,)):
                raise ValueError("Unsupported environment review schema")
            if versions:
                return
            db.execute("""CREATE TABLE sky_state.environment_reviews (
                workspace text NOT NULL,id uuid NOT NULL,application_id text NOT NULL,organization_id text NOT NULL,
                registration_id text NOT NULL,report_id text NOT NULL,document jsonb NOT NULL CHECK(jsonb_typeof(document)='object'),
                evaluated_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,
                recorded_by text NOT NULL,approved_by text,approved_at timestamptz,revoked_at timestamptz,
                approval_scope text NOT NULL DEFAULT 'environment_preservation_review_only'
                    CHECK(approval_scope='environment_preservation_review_only'),
                PRIMARY KEY(workspace,id),UNIQUE(workspace,application_id,registration_id,id),
                FOREIGN KEY(workspace,application_id) REFERENCES sky_state.application_owners(workspace,application_id),
                CHECK((approved_by IS NULL)=(approved_at IS NULL)))""")
            db.execute("""CREATE TABLE sky_state.environment_review_heads (
                workspace text NOT NULL,application_id text NOT NULL,registration_id text NOT NULL,review_id uuid NOT NULL,
                PRIMARY KEY(workspace,application_id,registration_id),
                FOREIGN KEY(workspace,application_id,registration_id,review_id)
                REFERENCES sky_state.environment_reviews(workspace,application_id,registration_id,id))""")
            db.execute("""CREATE TABLE sky_state.environment_review_audit (
                id uuid PRIMARY KEY,workspace text NOT NULL,review_id uuid NOT NULL,actor text NOT NULL,
                action text NOT NULL CHECK(action IN ('recorded','approved','revoked')),
                occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
                FOREIGN KEY(workspace,review_id) REFERENCES sky_state.environment_reviews(workspace,id))""")
            db.execute("INSERT INTO sky_state.environment_review_versions(version) VALUES(1)")

    def check_ready(self):
        with self.operations.records._connection() as db:
            if db.execute(
                "SELECT version FROM sky_state.environment_review_versions ORDER BY version"
            ).fetchall() != [(1,)]:
                raise ValueError("Environment reviews require explicit migration")
            db.execute(
                "SELECT report_id,document,expires_at,approved_by FROM sky_state.environment_reviews LIMIT 0"
            )

    @staticmethod
    def _expiry(document):
        deadline = datetime.fromisoformat(document["evaluated_at"]) + timedelta(
            seconds=document["max_age_seconds"]
        )
        for value in document["observations"]:
            deadline = min(
                deadline,
                datetime.fromisoformat(value["expires_at"]),
                datetime.fromisoformat(value["observed_at"]) + timedelta(seconds=document["max_age_seconds"]),
            )
        return deadline

    def _event(self, db, principal, identity, action):
        db.execute(
            "INSERT INTO sky_state.environment_review_audit(id,workspace,review_id,actor,action) VALUES(%s,%s,%s,%s,%s)",
            (str(uuid4()), self.operations.workspace, identity, principal.user_id, action),
        )

    @staticmethod
    def _result(identity, registration, document, expiry, approved):
        return EnvironmentPreservationReview(
            str(identity), registration, document["report_id"], expiry, approved
        )

    def record(self, principal, registration_id, document):
        self.authorizer._authorize(principal)
        _ref(registration_id)
        document = validate_environment_transition_report(document)
        scope = document["scope"]
        app = scope["application_id"]
        if scope["organization_id"] != principal.organization_id:
            raise FileNotFoundError("Environment review not found")
        evaluated = datetime.fromisoformat(document["evaluated_at"])
        expiry = self._expiry(document)
        with self.operations.records._connection() as db:
            self.authorizer._owner(db, principal, app)
            now = db.execute("SELECT clock_timestamp()").fetchone()[0]
            if evaluated > now:
                raise ValueError("Future environment review evaluation")
            old = db.execute(
                """SELECT r.id,r.report_id,r.evaluated_at,r.expires_at,r.approved_by
                FROM sky_state.environment_review_heads h JOIN sky_state.environment_reviews r
                ON r.workspace=h.workspace AND r.id=h.review_id
                WHERE h.workspace=%s AND h.application_id=%s AND h.registration_id=%s""",
                (self.operations.workspace, app, registration_id),
            ).fetchone()
            if old is not None:
                if old[1] == document["report_id"]:
                    return self._result(old[0], registration_id, document, old[3], old[4])
                if old[2] >= evaluated:
                    raise ValueError("New environment review is older or ambiguously ordered")
            identity = str(uuid4())
            db.execute(
                """INSERT INTO sky_state.environment_reviews
                (workspace,id,application_id,organization_id,registration_id,report_id,document,evaluated_at,expires_at,recorded_by)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    self.operations.workspace,
                    identity,
                    app,
                    principal.organization_id,
                    registration_id,
                    document["report_id"],
                    self.operations._json(document),
                    evaluated,
                    expiry,
                    principal.user_id,
                ),
            )
            db.execute(
                """INSERT INTO sky_state.environment_review_heads(workspace,application_id,registration_id,review_id)
                VALUES(%s,%s,%s,%s) ON CONFLICT(workspace,application_id,registration_id) DO UPDATE SET review_id=EXCLUDED.review_id""",
                (self.operations.workspace, app, registration_id, identity),
            )
            self._event(db, principal, identity, "recorded")
            return self._result(identity, registration_id, document, expiry, None)

    def _locked(self, db, principal, identity, registration_id, report_id):
        identity = self.operations._uuid(identity)
        _ref(registration_id)
        row = db.execute(
            "SELECT application_id,organization_id FROM sky_state.environment_reviews WHERE workspace=%s AND id=%s",
            (self.operations.workspace, identity),
        ).fetchone()
        if not row or row[1] != principal.organization_id:
            raise FileNotFoundError("Environment review not found")
        self.authorizer._owner(db, principal, row[0])
        value = db.execute(
            """SELECT r.document,r.expires_at,r.approved_by,r.revoked_at,
            r.expires_at>clock_timestamp(),h.review_id=r.id,r.registration_id,r.report_id
            FROM sky_state.environment_reviews r JOIN sky_state.environment_review_heads h
            ON h.workspace=r.workspace AND h.application_id=r.application_id AND h.registration_id=r.registration_id
            WHERE r.workspace=%s AND r.id=%s FOR UPDATE OF r""",
            (self.operations.workspace, identity),
        ).fetchone()
        if not value:
            raise ValueError("Environment review head missing")
        document = validate_environment_transition_report(value[0])
        scope = document["scope"]
        if (
            (scope["application_id"], scope["organization_id"]) != row
            or document["report_id"] != value[7]
            or (value[6], value[7]) != (registration_id, report_id)
            or value[1] != self._expiry(document)
            or value[3] is not None
            or value[4] is not True
            or value[5] is not True
            or document["status"] != "verified"
        ):
            raise ValueError("Environment review expired, superseded, revoked, changed or incomplete")
        return document, value

    def approve(self, principal, identity, *, registration_id, report_id):
        self.authorizer._authorize(principal)
        with self.operations.records._connection() as db:
            document, value = self._locked(db, principal, identity, registration_id, report_id)
            approved = value[2]
            if approved is None:
                approved = db.execute(
                    """UPDATE sky_state.environment_reviews SET approved_by=%s,approved_at=clock_timestamp()
                    WHERE workspace=%s AND id=%s AND expires_at>clock_timestamp() AND revoked_at IS NULL RETURNING approved_by""",
                    (principal.user_id, self.operations.workspace, identity),
                ).fetchone()
                if approved is None:
                    raise ValueError("Environment review expired during approval")
                approved = approved[0]
                self._event(db, principal, identity, "approved")
            return self._result(identity, registration_id, document, value[1], approved)

    def require(self, principal, identity, *, registration_id, report_id):
        self.authorizer._authorize(principal)
        with self.operations.records._connection() as db:
            document, value = self._locked(db, principal, identity, registration_id, report_id)
            if value[2] is None:
                raise ValueError("Environment preservation review not approved")
            return self._result(identity, registration_id, document, value[1], value[2])

    def revoke(self, principal, identity):
        self.authorizer._authorize(principal)
        identity = self.operations._uuid(identity)
        with self.operations.records._connection() as db:
            row = db.execute(
                "SELECT application_id,organization_id FROM sky_state.environment_reviews WHERE workspace=%s AND id=%s",
                (self.operations.workspace, identity),
            ).fetchone()
            if not row or row[1] != principal.organization_id:
                raise FileNotFoundError("Environment review not found")
            self.authorizer._owner(db, principal, row[0])
            changed = db.execute(
                "UPDATE sky_state.environment_reviews SET revoked_at=clock_timestamp() WHERE workspace=%s AND id=%s AND revoked_at IS NULL RETURNING id",
                (self.operations.workspace, identity),
            ).fetchone()
            if changed:
                self._event(db, principal, identity, "revoked")
            return changed is not None
