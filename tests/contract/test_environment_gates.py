"""Actual PostgreSQL gate history; observations are labelled test doubles."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from itertools import pairwise
from uuid import uuid4

import pytest

from adapters.state.deployment_admission import PostgresDeploymentAdmission
from adapters.state.environment_gates import PostgresPreservationGates
from adapters.state.operations import PostgresOperationStore
from domain.access import LoginSource, Principal, Role
from ports.operations import IdempotencyConflict
from tests.contract.test_database_migration_reviews import database as database  # noqa: PLC0414 -- fixture re-export
from tests.unit.test_environment_gate_review import case, observations


def actor():
    return Principal("alice", "org", Role.DEPLOYER, LoginSource.CORPORATE_SSO)


@pytest.fixture
def store(database):
    admission = PostgresDeploymentAdmission(
        PostgresOperationStore(database, workspace=uuid4().hex),
        account_id="111111111111",
        region="ap-northeast-2",
    )
    result = PostgresPreservationGates(admission, current_principal=lambda value: value)
    result.initialize()
    with database() as db:
        db.execute(
            "INSERT INTO sky_state.application_owners(workspace,application_id,organization_id,created_by) VALUES(%s,'app','org','alice')",
            (admission.operations.workspace,),
        )
    return result


def collected(database, policy, gate):
    with database() as db:
        now = db.execute("SELECT clock_timestamp()").fetchone()[0]
    return observations(policy, now - timedelta(seconds=1), through=gate)


def rows(store, database):
    with database() as db:
        return db.execute(
            "SELECT sequence,document FROM sky_state.environment_gate_records WHERE workspace=%s ORDER BY sequence",
            (store.operations.workspace,),
        ).fetchall()


def test_obligations_survive_restart_and_no_operation_is_admitted(store, database):
    policy, _ = case()
    first = store.record(actor(), "route", policy, "G0", (), request_key="first-collection")
    assert first["gate_status"] == "blocked" and len(first["obligations"]) == 20
    restarted = PostgresPreservationGates(store.admission, current_principal=lambda value: value)
    restarted.check_ready()
    assert restarted.latest(actor(), "route", policy) == first
    with database() as db:
        assert db.execute(
            "SELECT count(*) FROM sky_state.operations WHERE workspace=%s", (store.operations.workspace,)
        ).fetchone() == (0,)


def test_simultaneous_retries_are_one_immutable_record_and_changed_request_is_denied(store, database):
    policy, _ = case()
    evidence = collected(database, policy, "G0")
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(
            pool.map(
                lambda _: store.record(actor(), "route", policy, "G0", evidence, request_key="same-request"),
                range(8),
            )
        )
    assert len({value["record_id"] for value in results}) == 1 and len(rows(store, database)) == 1
    with pytest.raises(IdempotencyConflict):
        store.record(actor(), "route", policy, "G0", (), request_key="same-request")
    assert len(rows(store, database)) == 1


def test_concurrent_blocked_attempts_have_a_single_ordered_parent_chain(store, database):
    policy, _ = case()
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(
            pool.map(
                lambda index: store.record(
                    actor(), "route", policy, "G0", (), request_key="attempt-" + str(index)
                ),
                range(6),
            )
        )
    history = rows(store, database)
    assert [v[0] for v in history] == list(range(1, 7))
    assert history[0][1]["previous_record_id"] is None
    assert all(b[1]["previous_record_id"] == a[1]["record_id"] for a, b in pairwise(history))


def test_blocked_stage_cannot_be_skipped_and_old_verified_observations_do_not_refresh(store, database):
    policy, _ = case()
    evidence = collected(database, policy, "G0")
    first = store.record(actor(), "route", policy, "G0", evidence, request_key="g0")
    assert first["gate_status"] == "passed"
    second = store.record(actor(), "route", policy, "G1", evidence, request_key="g1")
    assert second["gate_status"] == "blocked" and "process_session_state" in second["blocking_obligations"]
    with pytest.raises(ValueError):
        store.record(actor(), "route", policy, "G2", collected(database, policy, "G2"), request_key="skip-g1")
    assert len(rows(store, database)) == 2
    fresh = collected(database, policy, "G1")
    fixed = store.record(actor(), "route", policy, "G1", fresh, request_key="g1-recollected")
    assert fixed["gate_status"] == "passed" and fixed["previous_record_id"] == second["record_id"]


def test_owner_revocation_and_tampered_obligations_do_not_publish_a_valid_history(store, database):
    policy, _ = case()
    store.record(actor(), "route", policy, "G0", (), request_key="first")
    with pytest.raises(FileNotFoundError):
        store.latest(replace(actor(), organization_id="other"), "route", policy)
    revoked = PostgresPreservationGates(store.admission, current_principal=lambda _: None)
    with pytest.raises(PermissionError):
        revoked.latest(actor(), "route", policy)
    with database() as db:
        db.execute(
            "UPDATE sky_state.environment_gate_records SET document=jsonb_set(document,'{obligations}','[]'::jsonb) WHERE workspace=%s",
            (store.operations.workspace,),
        )
    with pytest.raises(ValueError, match="persisted"):
        store.latest(actor(), "route", policy)
    with pytest.raises(ValueError):
        store.record(actor(), "route", policy, "G0", (), request_key="tampered-parent")


def test_membership_revoked_after_commit_returns_no_authority(store, database):
    policy, _ = case()
    calls = []

    def membership(value):
        calls.append(True)
        return value if len(calls) == 1 else None

    protected = PostgresPreservationGates(store.admission, current_principal=membership)
    with pytest.raises(PermissionError):
        protected.record(actor(), "route", policy, "G0", (), request_key="revoked-after-record")
    history = rows(store, database)
    assert len(history) == 1 and history[0][1]["execution_authorized"] is False
