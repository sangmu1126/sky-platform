"""Durable owner-bound workload dependency inventory reports.

This ledger stores collector output for G1 audit and gate evidence lookup. It
does not issue execution approval, create an operation or refresh evidence.
"""

from adapters.state.database_migration_reviews import PostgresMigrationReviews
from domain.workload_inventory import RegisteredWorkloadInventory
from engine.workload_inventory import validate_workload_inventory_report


class _BoundWorkloadInventoryPublisher:
    def __init__(self, store, principal, registration):
        self.store, self.principal, self.registration = store, principal, registration

    def publish(self, report):
        return self.store.record(self.principal, self.registration, report)


class PostgresWorkloadInventoryReports:
    def __init__(self, admission, *, current_principal):
        if not callable(current_principal):
            raise TypeError("Current workload inventory membership resolver required")
        self.admission, self.operations = admission, admission.operations
        self.authorizer = PostgresMigrationReviews(admission)
        self.current_principal = current_principal

    def initialize(self):
        self.admission.initialize()
        with self.operations.records._connection() as db:
            db.execute("SELECT pg_advisory_xact_lock(%s)", (self.operations.records.MIGRATION_LOCK,))
            db.execute("""CREATE TABLE IF NOT EXISTS sky_state.workload_inventory_report_versions (
                version integer PRIMARY KEY,applied_at timestamptz NOT NULL DEFAULT clock_timestamp())""")
            versions = db.execute(
                "SELECT version FROM sky_state.workload_inventory_report_versions ORDER BY version"
            ).fetchall()
            if versions not in ([], [(1,)]):
                raise ValueError("Unsupported workload inventory report schema")
            if versions:
                return
            db.execute("""CREATE TABLE sky_state.workload_inventory_reports (
                workspace text NOT NULL,report_id text NOT NULL,inventory_id text NOT NULL,
                application_id text NOT NULL,organization_id text NOT NULL,
                document jsonb NOT NULL CHECK(jsonb_typeof(document)='object'),
                evaluated_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,
                recorded_by text NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
                PRIMARY KEY(workspace,report_id),
                FOREIGN KEY(workspace,application_id)
                    REFERENCES sky_state.application_owners(workspace,application_id))""")
            db.execute("INSERT INTO sky_state.workload_inventory_report_versions(version) VALUES(1)")

    def check_ready(self):
        with self.operations.records._connection() as db:
            if db.execute(
                "SELECT version FROM sky_state.workload_inventory_report_versions ORDER BY version"
            ).fetchall() != [(1,)]:
                raise ValueError("Workload inventory reports require explicit migration")
            db.execute(
                "SELECT report_id,inventory_id,document FROM sky_state.workload_inventory_reports LIMIT 0"
            )

    def _live(self, principal, registration):
        self.authorizer._authorize(principal)
        if not isinstance(registration, RegisteredWorkloadInventory):
            raise TypeError("Registered workload inventory required")
        if registration.scope.organization_id != principal.organization_id:
            raise FileNotFoundError("Workload inventory not found")
        if self.current_principal(principal) != principal:
            raise PermissionError("Workload inventory membership changed")

    def publisher(self, principal, registration):
        self._live(principal, registration)
        return _BoundWorkloadInventoryPublisher(self, principal, registration)

    def record(self, principal, registration, report):
        self._live(principal, registration)
        document = validate_workload_inventory_report(registration, report)
        scope = document["scope"]
        inventory_id = registration.document()["inventory_id"]
        if (
            scope["organization_id"] != principal.organization_id
            or scope["application_id"] != registration.scope.application_id
            or document["inventory_id"] != inventory_id
        ):
            raise FileNotFoundError("Workload inventory not found")
        with self.operations.records._connection() as db:
            self.authorizer._owner(db, principal, registration.scope.application_id)
            if self.current_principal(principal) != principal:
                raise PermissionError("Workload inventory membership changed")
            db.execute(
                """INSERT INTO sky_state.workload_inventory_reports
                (workspace,report_id,inventory_id,application_id,organization_id,document,
                evaluated_at,expires_at,recorded_by)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                (
                    self.operations.workspace,
                    document["report_id"],
                    inventory_id,
                    registration.scope.application_id,
                    principal.organization_id,
                    self.operations._json(document),
                    document["evaluated_at"],
                    document["expires_at"],
                    principal.user_id,
                ),
            )
            stored = db.execute(
                """SELECT inventory_id,application_id,organization_id,document
                FROM sky_state.workload_inventory_reports
                WHERE workspace=%s AND report_id=%s FOR UPDATE""",
                (self.operations.workspace, document["report_id"]),
            ).fetchone()
            if stored != (
                inventory_id,
                registration.scope.application_id,
                principal.organization_id,
                document,
            ):
                raise ValueError("Stored workload inventory report differs")
        self._live(principal, registration)
        return document["report_id"]

    def read(self, principal, registration, report_id):
        self._live(principal, registration)
        with self.operations.records._connection() as db:
            self.authorizer._owner(db, principal, registration.scope.application_id)
            row = db.execute(
                """SELECT inventory_id,application_id,organization_id,document
                FROM sky_state.workload_inventory_reports WHERE workspace=%s AND report_id=%s""",
                (self.operations.workspace, report_id),
            ).fetchone()
            if row is None or row[:3] != (
                registration.document()["inventory_id"],
                registration.scope.application_id,
                principal.organization_id,
            ):
                raise FileNotFoundError("Workload inventory report not found")
            document = validate_workload_inventory_report(registration, row[3])
        self._live(principal, registration)
        return document
