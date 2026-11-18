"""Owner-bound, durable metadata reviews; no runtime DDL or operation admission.

New observations replace an app's review head. Previous reviews and audit events
are retained. Approval never turns an unsupported migration into an execution.
"""

from datetime import datetime
from uuid import uuid4

from application.database_migration_preflight import validate_preflight_report
from domain.access import Action, Principal, ResourceOwner, permitted
from ports.database_migration_reviews import MigrationPreflightReview, MigrationReviewUnavailable


class PostgresMigrationReviews:
    def __init__(self, admission):
        self.admission, self.operations = admission, admission.operations

    def initialize(self):
        """Explicit additive maintenance only, never called by review operations."""
        self.admission.initialize()
        with self.operations.records._connection() as db:
            db.execute("SELECT pg_advisory_xact_lock(%s)", (self.operations.records.MIGRATION_LOCK,))
            db.execute("""CREATE TABLE IF NOT EXISTS sky_state.migration_review_schema_versions (
                version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())""")
            versions = tuple(
                row[0]
                for row in db.execute(
                    "SELECT version FROM sky_state.migration_review_schema_versions ORDER BY version"
                ).fetchall()
            )
            if versions not in ((), (1,)):
                raise ValueError("Unsupported migration review schema")
            if versions:
                return
            db.execute("""CREATE TABLE sky_state.migration_preflight_reviews (
                workspace text NOT NULL, id uuid NOT NULL, application_id text NOT NULL,
                organization_id text NOT NULL, recorded_by text NOT NULL,
                plan_id text NOT NULL, evidence_id text NOT NULL,
                report jsonb NOT NULL CHECK(jsonb_typeof(report)='object'),
                observed_at timestamptz NOT NULL, expires_at timestamptz,
                created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
                approved_by text, approved_at timestamptz, revoked_at timestamptz,
                approval_scope text NOT NULL DEFAULT 'preflight_review_only'
                    CHECK(approval_scope='preflight_review_only'),
                PRIMARY KEY(workspace,id), UNIQUE(workspace,application_id,id),
                FOREIGN KEY(workspace,application_id) REFERENCES sky_state.application_owners(workspace,application_id),
                CHECK((approved_by IS NULL)=(approved_at IS NULL)))""")
            db.execute("""CREATE TABLE sky_state.migration_review_heads (
                workspace text NOT NULL, application_id text NOT NULL, review_id uuid NOT NULL,
                PRIMARY KEY(workspace,application_id),
                FOREIGN KEY(workspace,application_id,review_id)
                    REFERENCES sky_state.migration_preflight_reviews(workspace,application_id,id))""")
            db.execute("""CREATE TABLE sky_state.migration_review_audit (
                id uuid PRIMARY KEY, workspace text NOT NULL, review_id uuid NOT NULL,
                actor text NOT NULL, action text NOT NULL CHECK(action IN ('recorded','approved','revoked')),
                created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
                FOREIGN KEY(workspace,review_id) REFERENCES sky_state.migration_preflight_reviews(workspace,id))""")
            db.execute("INSERT INTO sky_state.migration_review_schema_versions(version) VALUES(1)")

    def check_ready(self):
        with self.operations.records._connection() as db:
            db.execute("SET TRANSACTION READ ONLY")
            db.execute("SET LOCAL statement_timeout='3s'")
            versions = tuple(
                row[0]
                for row in db.execute(
                    "SELECT version FROM sky_state.migration_review_schema_versions ORDER BY version"
                ).fetchall()
            )
            if versions != (1,):
                raise ValueError("Migration reviews must be migrated separately")
            db.execute(
                "SELECT workspace,id,report,approved_by,expires_at FROM sky_state.migration_preflight_reviews LIMIT 0"
            )
            db.execute(
                "SELECT workspace,application_id,review_id FROM sky_state.migration_review_heads LIMIT 0"
            )
            db.execute(
                "SELECT workspace,review_id,actor,action FROM sky_state.migration_review_audit LIMIT 0"
            )

    @staticmethod
    def _authorize(principal):
        if not isinstance(principal, Principal) or not permitted(
            principal, Action.DEPLOY, ResourceOwner(principal.organization_id, principal.user_id)
        ):
            raise PermissionError("Migration review access denied")

    def authorize(self, principal, application_id):
        self._authorize(principal)
        self.operations._text(application_id, "application identity")
        with self.operations.records._connection() as db:
            self._owner(db, principal, application_id)

    def _owner(self, db, principal, application_id):
        # Never adopt an unknown app just because its inventory was readable.
        row = db.execute(
            """SELECT organization_id,created_by FROM sky_state.application_owners
            WHERE workspace=%s AND application_id=%s FOR UPDATE""",
            (self.operations.workspace, application_id),
        ).fetchone()
        if row is None or not permitted(principal, Action.DEPLOY, ResourceOwner(*row)):
            raise FileNotFoundError("Application not found")

    def _event(self, db, principal, review_id, action):
        db.execute(
            """INSERT INTO sky_state.migration_review_audit(id,workspace,review_id,actor,action)
            VALUES(%s,%s,%s,%s,%s)""",
            (str(uuid4()), self.operations.workspace, review_id, principal.user_id, action),
        )

    @staticmethod
    def _result(identity, document, expires, approved_by):
        return MigrationPreflightReview(
            str(identity), document["plan_id"], document["preflight"]["evidence_id"], expires, approved_by
        )

    def record(self, principal, report):
        self._authorize(principal)
        document = validate_preflight_report(report)
        application = document["source"]["application_id"]
        if document["source"]["organization_id"] != principal.organization_id:
            raise FileNotFoundError("Application not found")
        observation = document["preflight"]
        observed = datetime.fromisoformat(observation["observed_at"])
        expires = datetime.fromisoformat(observation["expires_at"]) if observation["expires_at"] else None
        with self.operations.records._connection() as db:
            self._owner(db, principal, application)
            now = db.execute("SELECT clock_timestamp()").fetchone()[0]
            if observed > now:
                raise MigrationReviewUnavailable("Future observation cannot replace a current review")
            previous = db.execute(
                """SELECT r.id,r.observed_at,r.evidence_id,r.report,r.expires_at,r.approved_by
                FROM sky_state.migration_review_heads h JOIN sky_state.migration_preflight_reviews r
                ON r.workspace=h.workspace AND r.id=h.review_id
                WHERE h.workspace=%s AND h.application_id=%s""",
                (self.operations.workspace, application),
            ).fetchone()
            if previous:
                if previous[2] == observation["evidence_id"] and previous[3] == document:
                    return self._result(previous[0], document, previous[4], previous[5])
                if observed <= previous[1]:
                    raise MigrationReviewUnavailable(
                        "An older or ambiguous observation cannot replace a review"
                    )
                for inventory in observation["inventories"].values():
                    times = (inventory["observed_at"], inventory["resource"]["observed_at"])
                    if any(datetime.fromisoformat(at) < previous[1] for at in times):
                        raise MigrationReviewUnavailable(
                            "Overlapping stale observations require a fresh review"
                        )
            identity = str(uuid4())
            db.execute(
                """INSERT INTO sky_state.migration_preflight_reviews
                (workspace,id,application_id,organization_id,recorded_by,plan_id,evidence_id,report,observed_at,expires_at)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    self.operations.workspace,
                    identity,
                    application,
                    principal.organization_id,
                    principal.user_id,
                    document["plan_id"],
                    observation["evidence_id"],
                    self.operations._json(document),
                    observed,
                    expires,
                ),
            )
            db.execute(
                """INSERT INTO sky_state.migration_review_heads(workspace,application_id,review_id)
                VALUES(%s,%s,%s) ON CONFLICT(workspace,application_id) DO UPDATE SET review_id=excluded.review_id""",
                (self.operations.workspace, application, identity),
            )
            self._event(db, principal, identity, "recorded")
            return self._result(identity, document, expires, None)

    def _locked(self, db, principal, identity, plan_id, evidence_id):
        identity = self.operations._uuid(identity)
        row = db.execute(
            """SELECT application_id,organization_id FROM sky_state.migration_preflight_reviews
            WHERE workspace=%s AND id=%s""",
            (self.operations.workspace, identity),
        ).fetchone()
        if row is None or row[1] != principal.organization_id:
            raise FileNotFoundError("Migration review not found")
        self._owner(db, principal, row[0])
        record = db.execute(
            """SELECT r.report,r.expires_at,r.approved_by,r.revoked_at,
                r.expires_at>clock_timestamp(),h.review_id=r.id,r.plan_id,r.evidence_id
            FROM sky_state.migration_preflight_reviews r JOIN sky_state.migration_review_heads h
                ON h.workspace=r.workspace AND h.application_id=r.application_id
            WHERE r.workspace=%s AND r.id=%s FOR UPDATE OF r""",
            (self.operations.workspace, identity),
        ).fetchone()
        if record is None:
            raise MigrationReviewUnavailable("Review head missing")
        document = validate_preflight_report(record[0])
        if (document["source"]["application_id"], document["source"]["organization_id"]) != row:
            raise MigrationReviewUnavailable("Persisted application ownership differs from report")
        if (document["plan_id"], document["preflight"]["evidence_id"]) != (record[6], record[7]):
            raise MigrationReviewUnavailable("Persisted review identity differs from report")
        expiry = document["preflight"]["expires_at"]
        if record[1] != (datetime.fromisoformat(expiry) if expiry else None):
            raise MigrationReviewUnavailable("Persisted evidence expiration differs from report")
        if (document["plan_id"], document["preflight"]["evidence_id"]) != (plan_id, evidence_id):
            raise MigrationReviewUnavailable("Review source, target, policy or evidence changed")
        if (
            record[3] is not None
            or record[4] is not True
            or record[5] is not True
            or document["preflight"]["status"] != "passed"
        ):
            raise MigrationReviewUnavailable("Review expired, superseded, revoked or incomplete")
        return document, record

    def approve(self, principal, identity, *, plan_id, evidence_id):
        self._authorize(principal)
        with self.operations.records._connection() as db:
            document, record = self._locked(db, principal, identity, plan_id, evidence_id)
            approved_by = record[2]
            if approved_by is None:
                changed = db.execute(
                    """UPDATE sky_state.migration_preflight_reviews
                    SET approved_by=%s,approved_at=clock_timestamp() WHERE workspace=%s AND id=%s
                    AND expires_at>clock_timestamp() AND revoked_at IS NULL RETURNING approved_by""",
                    (principal.user_id, self.operations.workspace, identity),
                ).fetchone()
                if changed is None:
                    raise MigrationReviewUnavailable("Review expired before approval")
                approved_by = changed[0]
                self._event(db, principal, identity, "approved")
            return self._result(identity, document, record[1], approved_by)

    def require(self, principal, identity, *, plan_id, evidence_id):
        self._authorize(principal)
        with self.operations.records._connection() as db:
            document, record = self._locked(db, principal, identity, plan_id, evidence_id)
            if record[2] is None:
                raise MigrationReviewUnavailable("Preflight review not approved")
            return self._result(identity, document, record[1], record[2])

    def revoke(self, principal, identity):
        self._authorize(principal)
        identity = self.operations._uuid(identity)
        with self.operations.records._connection() as db:
            row = db.execute(
                """SELECT application_id,organization_id FROM sky_state.migration_preflight_reviews
                WHERE workspace=%s AND id=%s""",
                (self.operations.workspace, identity),
            ).fetchone()
            if row is None or row[1] != principal.organization_id:
                raise FileNotFoundError("Migration review not found")
            self._owner(db, principal, row[0])
            changed = db.execute(
                """UPDATE sky_state.migration_preflight_reviews SET revoked_at=clock_timestamp()
                WHERE workspace=%s AND id=%s AND revoked_at IS NULL RETURNING id""",
                (self.operations.workspace, identity),
            ).fetchone()
            if changed:
                self._event(db, principal, identity, "revoked")
            return changed is not None
