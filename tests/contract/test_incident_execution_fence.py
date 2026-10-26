"""Real PostgreSQL serialization between incident barriers and worker effects."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Event

import pytest

from adapters.state.incident_execution import PostgresIncidentExecutionControl
from application.security_hold import SecurityHold, require_no_security_hold
from domain.access import Role
from ports.operations import ApplicationBusy
from ports.state import RecordConflict
from tests.contract.test_operation_store import database as database  # noqa: PLC0414
from tests.contract.test_operation_store import store as store  # noqa: PLC0414
from tests.unit.test_deployment_writes import ID, Records, principal


@pytest.fixture
def incident(store):
    actor = principal(role=Role.ADMIN)
    job = Records().job
    store.records.save_job(ID, job)
    SecurityHold(store.records).place(
        actor, ID, incident_id="INC-1", reason="credential_exposure", now="2026-10-26T00:00:00+00:00"
    )
    snapshot = store.records.load_job(ID)
    return actor, {
        "incident_id": "INC-1",
        "expected_boundary": snapshot.record["security_review_boundary"]["id"],
        "expected_revision": snapshot.revision,
    }


def test_fence_blocks_queued_claim_admission_and_survives_expiry(store, incident):
    actor, options = incident
    operation = store.admit("game", "deploy", "one", {})
    service = PostgresIncidentExecutionControl(store, revalidate=lambda: actor)
    result = service.fence(actor, ID, **options)
    assert result["sky_operation_admission_fenced"]
    assert result["registered_operation_requests_settled"]
    assert not result["execution_exclusion_verified"] and result["state_changed"]
    assert store.claim(operation.id, operation.attempt_id, "worker") is None
    with pytest.raises(ApplicationBusy, match="fenced"):
        store.admit("game", "deploy", "two", {})
    with pytest.raises(ValueError, match="Execution fencing"):
        require_no_security_hold({"security_execution_fence": {}})
    options["expected_revision"] = result["metadata_revision"]
    observed = service.inspect(actor, ID, **options)
    assert observed["read_only"] and not observed["state_changed"]
    assert service.fence(actor, ID, **options)["state_changed"] is False
    other = store.admit("other-app", "deploy", "unrelated", {})
    assert store.claim(other.id, other.attempt_id, "other")


def test_existing_lease_cannot_start_or_overwrite_external_intent_after_fence(store, incident):
    actor, options = incident
    op = store.admit("game", "deploy", "one", {})
    lease = store.claim(op.id, op.attempt_id, "worker")
    assert store.begin_external(lease, {"service": "registered", "request": "original"})
    before = store.get(op.id)
    report = PostgresIncidentExecutionControl(store, revalidate=lambda: actor).fence(actor, ID, **options)
    assert report["pending_operation_ids"] == [op.id]
    assert not report["registered_operation_requests_settled"]
    assert not store.heartbeat(lease)
    assert not store.begin_external(lease, {"request": "overwrite"})
    assert not store.observe_external(lease, {"fake": True}, {})
    assert not store.complete(lease, {})
    assert store.get(op.id) == before
    assert store.recover_expired() == ()


def test_fence_serializes_with_already_admitted_external_intent(store, incident):
    actor, options = incident
    op = store.admit("game", "deploy", "one", {})
    lease = store.claim(op.id, op.attempt_id, "worker")
    locked, release = Event(), Event()

    def external_intent():
        with store.records._connection() as db:
            assert store._owned(db, lease)
            locked.set()
            assert release.wait(10)
            db.execute(
                "UPDATE sky_state.operations SET external_pending=true,external_intent=%s WHERE workspace=%s AND id=%s",
                (store._json({"request": "in-flight"}), store.workspace, op.id),
            )

    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = pool.submit(external_intent)
        assert locked.wait(10)
        barrier = pool.submit(
            PostgresIncidentExecutionControl(store, revalidate=lambda: actor).fence, actor, ID, **options
        )
        release.set()
        pending.result(timeout=10)
        report = barrier.result(timeout=10)
    assert report["pending_operation_ids"] == [op.id]
    assert not store.begin_external(lease, {"request": "late"})


@pytest.mark.parametrize("change", ["revision", "boundary", "organization", "revoked"])
def test_invalid_scope_never_installs_barrier(store, incident, change):
    actor, options = incident
    if change == "revision":
        options["expected_revision"] += 1
    if change == "boundary":
        options["expected_boundary"] = "f" * 32
    if change == "organization":
        actor = replace(actor, organization_id="other")
    current = replace(actor, role=Role.VIEWER) if change == "revoked" else actor
    with pytest.raises((ValueError, PermissionError, FileNotFoundError, RecordConflict)):
        PostgresIncidentExecutionControl(store, revalidate=lambda: current).fence(actor, ID, **options)
    assert store.admit("game", "deploy", "still-open", {})


def test_old_worker_sql_cannot_bypass_barrier_by_ignoring_new_python_checks(store, incident, database):
    actor, options = incident
    op = store.admit("game", "deploy", "old-sql-client", {})
    lease = store.claim(op.id, op.attempt_id, "old-worker", seconds=3600)
    PostgresIncidentExecutionControl(store, revalidate=lambda: actor).fence(actor, ID, **options)
    import psycopg

    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState), database() as db:
        db.execute(
            "UPDATE sky_state.operations SET external_pending=true WHERE workspace=%s AND id=%s",
            (store.workspace, op.id),
        )
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState), database() as db:
        db.execute(
            "UPDATE sky_state.operations SET lease_until=clock_timestamp()+interval '1 hour' WHERE workspace=%s AND id=%s",
            (store.workspace, op.id),
        )
    assert not store.get(op.id).external_pending
    assert not store.begin_external(lease, {"attempt": "bypass"})


def test_expired_fenced_worker_parks_and_is_never_requeued(store, incident, database):
    actor, options = incident
    op = store.admit("game", "deploy", "expired-fenced", {})
    store.claim(op.id, op.attempt_id, "worker", seconds=1)
    # Model the expiration before admission of the fence, not a raw SQL bypass afterward.
    with database() as db:
        db.execute(
            "UPDATE sky_state.operations SET lease_until=clock_timestamp()-interval '1 second' WHERE workspace=%s AND id=%s",
            (store.workspace, op.id),
        )
    PostgresIncidentExecutionControl(store, revalidate=lambda: actor).fence(actor, ID, **options)
    assert store.recover_expired() == (op.id,)
    assert store.get(op.id).status == "needs_attention"
    assert store.claim(op.id, op.attempt_id, "new-worker") is None


def test_restricted_worker_lookup_and_trigger_need_no_access_to_incident_records(store, incident, database):
    from uuid import uuid4

    import psycopg
    from psycopg import sql

    actor, options = incident
    op = store.admit("game", "deploy", "restricted-worker", {})
    store.claim(op.id, op.attempt_id, "worker")
    PostgresIncidentExecutionControl(store, revalidate=lambda: actor).fence(actor, ID, **options)
    role = "sky_incident_worker_" + uuid4().hex[:12]
    with database() as db:
        db.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
        db.execute(sql.SQL("GRANT USAGE ON SCHEMA sky_state TO {}").format(sql.Identifier(role)))
        db.execute(sql.SQL("GRANT SELECT,UPDATE ON sky_state.operations TO {}").format(sql.Identifier(role)))
    try:
        with database() as db:
            db.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(role)))
            assert db.execute(
                "SELECT has_table_privilege(current_user,'sky_state.incident_execution_fences','SELECT')"
            ).fetchone() == (False,)
            assert db.execute(
                "SELECT sky_state.incident_execution_allowed(%s,%s)", (store.workspace, "game")
            ).fetchone() == (False,)
            assert db.execute(
                "SELECT sky_state.incident_execution_allowed(%s,%s)", (store.workspace, "other")
            ).fetchone() == (True,)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState), database() as db:
            db.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(role)))
            db.execute(
                "UPDATE sky_state.operations SET external_pending=true WHERE workspace=%s AND id=%s",
                (store.workspace, op.id),
            )
    finally:
        with database() as db:
            db.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            db.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
