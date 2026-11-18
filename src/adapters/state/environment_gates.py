"""Append-only, owner-bound stage obligations in PostgreSQL.

Only trusted registry/collector composition calls this adapter. A persisted
stage pass is not an executor lease, user consent or a provider operation.
Current identity is reloaded around transactions; an after-commit revocation
may leave an unapproved history record, but cannot authorize an effect.
"""

import hashlib
import json
from dataclasses import asdict

from adapters.state.database_migration_reviews import PostgresMigrationReviews
from application.environment_gate_review import (
    RegisteredPreservationGatePolicy,
    advance_preservation_gate,
    validate_preservation_gate_record,
)
from domain.environment_transition import PreservationObservation, _ref
from ports.operations import IdempotencyConflict


class PostgresPreservationGates:
    def __init__(self, admission, *, current_principal):
        if not callable(current_principal):
            raise TypeError("Current gate membership resolver required")
        self.admission, self.operations = admission, admission.operations
        self.authorizer = PostgresMigrationReviews(admission)
        self.current_principal = current_principal

    def initialize(self):
        self.admission.initialize()
        with self.operations.records._connection() as db:
            db.execute("SELECT pg_advisory_xact_lock(%s)", (self.operations.records.MIGRATION_LOCK,))
            db.execute("""CREATE TABLE IF NOT EXISTS sky_state.environment_gate_versions (
                version integer PRIMARY KEY,applied_at timestamptz NOT NULL DEFAULT clock_timestamp())""")
            versions = db.execute(
                "SELECT version FROM sky_state.environment_gate_versions ORDER BY version"
            ).fetchall()
            if versions not in ([], [(1,)]):
                raise ValueError("Unsupported preservation gate schema")
            if versions:
                return
            db.execute("""CREATE TABLE sky_state.environment_gate_records (
                workspace text NOT NULL,application_id text NOT NULL,organization_id text NOT NULL,
                registration_id text NOT NULL,policy_id text NOT NULL,sequence bigint NOT NULL CHECK(sequence>0),
                request_key text NOT NULL,request_fingerprint text NOT NULL,
                policy_document jsonb NOT NULL CHECK(jsonb_typeof(policy_document)='object'),
                document jsonb NOT NULL CHECK(jsonb_typeof(document)='object'),
                recorded_by text NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
                PRIMARY KEY(workspace,registration_id,policy_id,sequence),
                UNIQUE(workspace,registration_id,policy_id,request_key),
                FOREIGN KEY(workspace,application_id) REFERENCES sky_state.application_owners(workspace,application_id))""")
            db.execute("INSERT INTO sky_state.environment_gate_versions(version) VALUES(1)")

    def check_ready(self):
        with self.operations.records._connection() as db:
            if db.execute(
                "SELECT version FROM sky_state.environment_gate_versions ORDER BY version"
            ).fetchall() != [(1,)]:
                raise ValueError("Preservation gates require explicit migration")
            db.execute(
                "SELECT policy_id,document,sequence,request_fingerprint FROM sky_state.environment_gate_records LIMIT 0"
            )

    def _live(self, principal, policy):
        self.authorizer._authorize(principal)
        if not isinstance(policy, RegisteredPreservationGatePolicy):
            raise TypeError("Registered preservation policy required")
        if policy.scope.organization_id != principal.organization_id:
            raise FileNotFoundError("Preservation gate not found")
        if self.current_principal(principal) != principal:
            raise PermissionError("Preservation gate membership changed")

    @staticmethod
    def _request(policy, gate, observations):
        if (
            not isinstance(observations, tuple)
            or len(observations) > 128
            or any(not isinstance(v, PreservationObservation) for v in observations)
        ):
            raise ValueError("Bounded registered gate observations required")
        # Stable content identity; no expiry or scope is refreshed on a replay.
        values = [
            asdict(v) for v in sorted(observations, key=lambda v: (v.requirement.capability, v.endpoint))
        ]
        value = {"policy_id": policy.document()["policy_id"], "gate": gate, "observations": values}
        raw = json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False, default=lambda v: v.isoformat()
        )
        if len(raw.encode()) > 256 * 1024:
            raise ValueError("Bounded gate request required")
        return hashlib.sha256(raw.encode()).hexdigest()

    def record(self, principal, registration_id, policy, gate, observations, *, request_key):
        self._live(principal, policy)
        _ref(registration_id)
        _ref(request_key)
        fingerprint = self._request(policy, gate, observations)
        policy_document = policy.document()
        identity = policy_document["policy_id"]
        key = (self.operations.workspace, registration_id, identity)
        with self.operations.records._connection() as db:
            # This existing lock serializes gate writers for the app. Runtime
            # needs only the harmless owner-row UPDATE column used for the lock.
            self.authorizer._owner(db, principal, policy.scope.application_id)
            previous_request = db.execute(
                "SELECT request_fingerprint,document,policy_document,application_id,organization_id FROM sky_state.environment_gate_records WHERE workspace=%s AND registration_id=%s AND policy_id=%s AND request_key=%s",
                (*key, request_key),
            ).fetchone()
            if previous_request:
                if previous_request[0] != fingerprint or previous_request[2:] != (
                    policy_document,
                    policy.scope.application_id,
                    principal.organization_id,
                ):
                    raise IdempotencyConflict(
                        "Gate request key already belongs to another immutable collection"
                    )
                document = validate_preservation_gate_record(policy, previous_request[1])
            else:
                previous = db.execute(
                    "SELECT sequence,document,policy_document,application_id,organization_id FROM sky_state.environment_gate_records WHERE workspace=%s AND registration_id=%s AND policy_id=%s ORDER BY sequence DESC LIMIT 1",
                    key,
                ).fetchone()
                if previous and previous[2:] != (
                    policy_document,
                    policy.scope.application_id,
                    principal.organization_id,
                ):
                    raise ValueError("Stored preservation gate ownership or policy changed")
                now = db.execute("SELECT clock_timestamp()").fetchone()[0]
                document = advance_preservation_gate(
                    policy, None if previous is None else previous[1], gate, observations, now=now
                )
                sequence = 1 if previous is None else previous[0] + 1
                db.execute(
                    "INSERT INTO sky_state.environment_gate_records(workspace,application_id,organization_id,registration_id,policy_id,sequence,request_key,request_fingerprint,policy_document,document,recorded_by) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (
                        self.operations.workspace,
                        policy.scope.application_id,
                        principal.organization_id,
                        registration_id,
                        identity,
                        sequence,
                        request_key,
                        fingerprint,
                        self.operations._json(policy_document),
                        self.operations._json(document),
                        principal.user_id,
                    ),
                )
        self._live(principal, policy)
        return document

    def latest(self, principal, registration_id, policy):
        self._live(principal, policy)
        _ref(registration_id)
        with self.operations.records._connection() as db:
            self.authorizer._owner(db, principal, policy.scope.application_id)
            row = db.execute(
                "SELECT document,policy_document,application_id,organization_id FROM sky_state.environment_gate_records WHERE workspace=%s AND registration_id=%s AND policy_id=%s ORDER BY sequence DESC LIMIT 1",
                (self.operations.workspace, registration_id, policy.document()["policy_id"]),
            ).fetchone()
            if not row:
                raise FileNotFoundError("Preservation gate not found")
            if row[1:] != (policy.document(), policy.scope.application_id, principal.organization_id):
                raise ValueError("Stored preservation gate scope changed")
            result = validate_preservation_gate_record(policy, row[0])
        self._live(principal, policy)
        return result
