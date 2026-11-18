"""Real PostgreSQL review transactions; collectors are explicit test doubles.

These tests do not claim workload preservation or migration execution.
"""

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

import pytest

from adapters.state.deployment_admission import PostgresDeploymentAdmission
from adapters.state.environment_reviews import PostgresEnvironmentReviews
from adapters.state.operations import PostgresOperationStore
from domain.access import LoginSource, Principal, Role
from engine.environment_transition import assess_environment_transition
from tests.contract.test_database_migration_reviews import database as database  # noqa: PLC0414 -- pytest fixture re-export
from tests.unit.test_environment_transition import setup


def actor(role=Role.DEPLOYER, org="org"):
    return Principal("alice", org, role, LoginSource.CORPORATE_SSO)


@pytest.fixture
def store(database):
    value = PostgresEnvironmentReviews(
        PostgresDeploymentAdmission(
            PostgresOperationStore(database, workspace=uuid4().hex),
            account_id="111111111111",
            region="ap-northeast-2",
        )
    )
    value.initialize()
    with database() as db:
        db.execute(
            "INSERT INTO sky_state.application_owners(workspace,application_id,organization_id,created_by) VALUES(%s,'app','org','alice')",
            (value.operations.workspace,),
        )
    return value


def report(database, *, missing=False, seconds_old=1, expires_seconds=60):
    scope, requirements, observations = setup()
    with database() as db:
        now = db.execute("SELECT clock_timestamp()").fetchone()[0]
    evaluated = now - timedelta(seconds=seconds_old)
    values = tuple(
        replace(
            v,
            observed_at=evaluated - timedelta(seconds=1),
            expires_at=now + timedelta(seconds=expires_seconds),
        )
        for v in observations
    )
    return assess_environment_transition(
        scope, requirements, () if missing else values, now=evaluated, max_age_seconds=60
    )


def args(review):
    return {"registration_id": review.registration_id, "report_id": review.report_id}


def test_review_survives_restart_and_approval_never_creates_an_operation(store, database):
    value = store.record(actor(), "registered-route", report(database))
    with pytest.raises(ValueError, match="not approved"):
        store.require(actor(), value.id, **args(value))
    fresh = PostgresEnvironmentReviews(store.admission)
    approved = fresh.approve(actor(), value.id, **args(value))
    assert fresh.require(actor(), value.id, **args(value)) == approved
    assert (
        approved.approval_scope == "environment_preservation_review_only"
        and not approved.execution_authorized
    )
    fresh.check_ready()
    with database() as db:
        assert db.execute(
            "SELECT count(*) FROM sky_state.operations WHERE workspace=%s", (store.operations.workspace,)
        ).fetchone() == (0,)
        assert db.execute(
            "SELECT action FROM sky_state.environment_review_audit WHERE workspace=%s ORDER BY occurred_at",
            (store.operations.workspace,),
        ).fetchall() == [("recorded",), ("approved",)]


def test_concurrent_record_and_approval_are_idempotent(store, database):
    document = report(database)
    with ThreadPoolExecutor(max_workers=5) as pool:
        values = list(pool.map(lambda _: store.record(actor(), "registered-route", document), range(10)))
    assert len(set(values)) == 1
    value = values[0]
    with ThreadPoolExecutor(max_workers=5) as pool:
        approved = list(pool.map(lambda _: store.approve(actor(), value.id, **args(value)), range(10)))
    assert len(set(approved)) == 1


def test_new_failed_collection_supersedes_old_approval_without_changing_other_route(store, database):
    first = store.record(actor(), "route-a", report(database))
    store.approve(actor(), first.id, **args(first))
    other = store.record(actor(), "route-b", report(database))
    store.approve(actor(), other.id, **args(other))
    blocked = store.record(actor(), "route-a", report(database, missing=True, seconds_old=0.5))
    with pytest.raises(ValueError):
        store.require(actor(), first.id, **args(first))
    with pytest.raises(ValueError):
        store.approve(actor(), blocked.id, **args(blocked))
    assert store.require(actor(), other.id, **args(other)).approved_by == "alice"


def test_older_collection_and_changed_identity_do_not_replace_head(store, database):
    original = store.record(actor(), "registered-route", report(database))
    with pytest.raises(ValueError, match="older"):
        store.record(actor(), "registered-route", report(database, seconds_old=30))
    with pytest.raises(ValueError):
        store.approve(actor(), original.id, registration_id="wrong-route", report_id=original.report_id)
    with pytest.raises(ValueError):
        store.approve(
            actor(), original.id, registration_id=original.registration_id, report_id="ENV-" + "f" * 64
        )
    assert store.approve(actor(), original.id, **args(original)).approved_by == "alice"


def test_expiry_revocation_and_membership_permissions_are_not_reusable(store, database):
    short = store.record(actor(), "short-route", report(database, expires_seconds=0.2))
    time.sleep(0.25)
    with pytest.raises(ValueError):
        store.approve(actor(), short.id, **args(short))
    value = store.record(actor(), "registered-route", report(database))
    with pytest.raises(PermissionError):
        store.approve(actor(Role.VIEWER), value.id, **args(value))
    with pytest.raises(FileNotFoundError):
        store.approve(actor(org="other"), value.id, **args(value))
    store.approve(actor(), value.id, **args(value))
    assert store.revoke(actor(), value.id) and not store.revoke(actor(), value.id)
    with pytest.raises(ValueError):
        store.require(actor(), value.id, **args(value))


def test_audit_failure_rolls_back_record_and_approval(store, database):
    with patch.object(store, "_event", side_effect=OSError("audit unavailable")), pytest.raises(OSError):
        store.record(actor(), "registered-route", report(database))
    value = store.record(actor(), "registered-route", report(database))
    with patch.object(store, "_event", side_effect=OSError("audit unavailable")), pytest.raises(OSError):
        store.approve(actor(), value.id, **args(value))
    with pytest.raises(ValueError, match="not approved"):
        store.require(actor(), value.id, **args(value))
