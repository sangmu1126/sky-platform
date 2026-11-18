"""Durable owner-bound provider/resource identity evidence."""

from adapters.runtime.provider_identity import (
    RegisteredProviderIdentityInventory,
    validate_provider_identity_report,
)
from adapters.state.database_migration_reviews import PostgresMigrationReviews


class _BoundProviderIdentityPublisher:
    def __init__(self, store, principal, registration):
        self.store, self.principal, self.registration = store, principal, registration

    def publish(self, report):
        return self.store.record(self.principal, self.registration, report)


class PostgresProviderIdentityReports:
    def __init__(self, admission, *, current_principal):
        if not callable(current_principal):
            raise TypeError("Current provider identity membership resolver required")
        self.admission, self.operations = admission, admission.operations
        self.authorizer = PostgresMigrationReviews(admission)
        self.current_principal = current_principal

    def initialize(self):
        self.admission.initialize()
        with self.operations.records._connection() as db:
            db.execute("SELECT pg_advisory_xact_lock(%s)", (self.operations.records.MIGRATION_LOCK,))
            db.execute("""CREATE TABLE IF NOT EXISTS sky_state.provider_identity_report_versions (
                version integer PRIMARY KEY,applied_at timestamptz NOT NULL DEFAULT clock_timestamp())""")
            versions = db.execute(
                "SELECT version FROM sky_state.provider_identity_report_versions ORDER BY version"
            ).fetchall()
            if versions not in ([], [(1,)]):
                raise ValueError("Unsupported provider identity report schema")
            if versions:
                return
            db.execute("""CREATE TABLE sky_state.provider_identity_reports (
                workspace text NOT NULL,report_id text NOT NULL,
                provider_identity_registration_id text NOT NULL,inventory_id text NOT NULL,
                application_id text NOT NULL,organization_id text NOT NULL,
                endpoint text NOT NULL CHECK(endpoint IN ('source','target')),
                document jsonb NOT NULL CHECK(jsonb_typeof(document)='object'),
                evaluated_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,
                recorded_by text NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
                PRIMARY KEY(workspace,report_id),
                FOREIGN KEY(workspace,application_id)
                    REFERENCES sky_state.application_owners(workspace,application_id))""")
            db.execute("INSERT INTO sky_state.provider_identity_report_versions(version) VALUES(1)")

    def check_ready(self):
        with self.operations.records._connection() as db:
            if db.execute(
                "SELECT version FROM sky_state.provider_identity_report_versions ORDER BY version"
            ).fetchall() != [(1,)]:
                raise ValueError("Provider identity reports require explicit migration")
            db.execute(
                "SELECT report_id,provider_identity_registration_id,document "
                "FROM sky_state.provider_identity_reports LIMIT 0"
            )

    def _live(self, principal, registration):
        self.authorizer._authorize(principal)
        if not isinstance(registration, RegisteredProviderIdentityInventory):
            raise TypeError("Registered provider identity inventory required")
        if registration.inventory.scope.organization_id != principal.organization_id:
            raise FileNotFoundError("Provider identity report not found")
        if self.current_principal(principal) != principal:
            raise PermissionError("Provider identity membership changed")

    def publisher(self, principal, registration):
        self._live(principal, registration)
        return _BoundProviderIdentityPublisher(self, principal, registration)

    def record(self, principal, registration, report):
        self._live(principal, registration)
        document = validate_provider_identity_report(registration, report)
        registered = registration.document()
        inventory = registration.inventory
        with self.operations.records._connection() as db:
            self.authorizer._owner(db, principal, inventory.scope.application_id)
            if self.current_principal(principal) != principal:
                raise PermissionError("Provider identity membership changed")
            db.execute(
                """INSERT INTO sky_state.provider_identity_reports
                (workspace,report_id,provider_identity_registration_id,inventory_id,application_id,
                organization_id,endpoint,document,evaluated_at,expires_at,recorded_by)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                (
                    self.operations.workspace,
                    document["report_id"],
                    registered["provider_identity_registration_id"],
                    registered["inventory_id"],
                    inventory.scope.application_id,
                    principal.organization_id,
                    registration.endpoint,
                    self.operations._json(document),
                    document["evaluated_at"],
                    document["expires_at"],
                    principal.user_id,
                ),
            )
            row = db.execute(
                """SELECT provider_identity_registration_id,inventory_id,application_id,
                organization_id,endpoint,document FROM sky_state.provider_identity_reports
                WHERE workspace=%s AND report_id=%s FOR UPDATE""",
                (self.operations.workspace, document["report_id"]),
            ).fetchone()
            if row != (
                registered["provider_identity_registration_id"],
                registered["inventory_id"],
                inventory.scope.application_id,
                principal.organization_id,
                registration.endpoint,
                document,
            ):
                raise ValueError("Stored provider identity report differs")
        self._live(principal, registration)
        return document["report_id"]

    def read(self, principal, registration, report_id):
        self._live(principal, registration)
        registered = registration.document()
        inventory = registration.inventory
        with self.operations.records._connection() as db:
            self.authorizer._owner(db, principal, inventory.scope.application_id)
            row = db.execute(
                """SELECT provider_identity_registration_id,inventory_id,application_id,
                organization_id,endpoint,document FROM sky_state.provider_identity_reports
                WHERE workspace=%s AND report_id=%s""",
                (self.operations.workspace, report_id),
            ).fetchone()
            if row is None or row[:5] != (
                registered["provider_identity_registration_id"],
                registered["inventory_id"],
                inventory.scope.application_id,
                principal.organization_id,
                registration.endpoint,
            ):
                raise FileNotFoundError("Provider identity report not found")
            document = validate_provider_identity_report(registration, row[5])
        self._live(principal, registration)
        return document
