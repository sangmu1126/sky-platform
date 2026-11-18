"""Actual PostgreSQL transactions for metadata reviews; inventory is controlled.

Requires an explicit disposable control-state database. This is not a migration
execution test or proof of cloud provider ownership.
"""

import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

import pytest

psycopg = pytest.importorskip("psycopg")

from adapters.state.database_migration_reviews import PostgresMigrationReviews
from adapters.state.deployment_admission import PostgresDeploymentAdmission
from adapters.state.operations import PostgresOperationStore
from application.database_migration_preflight import DatabaseMigrationPreflight
from domain.access import LoginSource, Principal, Role
from domain.database_migration import MigrationSafetyPolicy
from engine.database_migration import plan_database_migration
from ports.database_migration_reviews import MigrationReviewUnavailable
from tests.contract.test_migration_inventory import databases as databases  # noqa: PLC0414 -- pytest fixture re-export
from tests.unit.test_database_migration_preflight import case as case  # noqa: PLC0414 -- pytest fixture re-export


@pytest.fixture(scope="module")
def database():
    dsn = os.environ.get("SKY_TEST_MIGRATION_STATE_DSN")
    if not dsn:
        pytest.skip("Explicit disposable migration review database required")
    parameters = psycopg.conninfo.conninfo_to_dict(dsn)
    assert parameters["host"] == "127.0.0.1" and parameters["dbname"].startswith("sky_migration_state_")
    connect = lambda: psycopg.connect(**parameters)

    def initialize(_):
        PostgresMigrationReviews(
            PostgresDeploymentAdmission(
                PostgresOperationStore(connect),
                account_id="111111111111",
                region="ap-northeast-2",
            )
        ).initialize()

    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(initialize, range(3)))
    return connect


def actor(role=Role.DEPLOYER, org="org", user="alice"):
    return Principal(user, org, role, LoginSource.CORPORATE_SSO)


@pytest.fixture
def store(database):
    store = PostgresMigrationReviews(
        PostgresDeploymentAdmission(
            PostgresOperationStore(database, workspace=uuid4().hex),
            account_id="111111111111",
            region="ap-northeast-2",
        )
    )
    with database() as db:
        db.execute(
            "INSERT INTO sky_state.application_owners(workspace,application_id,organization_id,created_by) VALUES(%s,'app','org','alice')",
            (store.operations.workspace,),
        )
    return store


def report(case, database, *, max_age=60, old_seconds=1):
    with database() as db:
        now = db.execute("SELECT clock_timestamp()").fetchone()[0] - timedelta(seconds=old_seconds)
    source, target, safety, readers = case
    identity = plan_database_migration(source, target, safety, source_revision="a" * 64)["plan_id"]
    for reader, placement in zip(readers, (source, target)):
        old = reader.inspect.return_value
        reader.inspect.return_value = replace(
            old,
            plan_id=identity,
            placement=placement,
            observed_at=now,
            resource=replace(old.resource, placement=placement, observed_at=now),
        )
    return DatabaseMigrationPreflight(*readers, clock=lambda: now, max_age_seconds=max_age).inspect(
        source,
        target,
        safety,
        source_revision="a" * 64,
    )


def args(review):
    return {"plan_id": review.plan_id, "evidence_id": review.evidence_id}


def test_persistence_restart_approval_audit_and_no_execution(store, database, case):
    value = store.record(actor(), report(case, database))
    with pytest.raises(MigrationReviewUnavailable):
        store.require(actor(), value.id, **args(value))
    store = PostgresMigrationReviews(store.admission)
    approved = store.approve(actor(), value.id, **args(value))
    assert store.require(actor(), value.id, **args(value)) == approved
    assert approved.approval_scope == "preflight_review_only" and not approved.execution_authorized
    store.check_ready()
    with database() as db:
        events = db.execute(
            "SELECT action FROM sky_state.migration_review_audit WHERE workspace=%s ORDER BY created_at",
            (store.operations.workspace,),
        ).fetchall()
        operations = db.execute(
            "SELECT count(*) FROM sky_state.operations WHERE workspace=%s", (store.operations.workspace,)
        ).fetchone()[0]
    assert events == [("recorded",), ("approved",)] and operations == 0


def test_concurrent_identical_record_and_approve_are_idempotent(store, database, case):
    document = report(case, database)
    with ThreadPoolExecutor(max_workers=6) as pool:
        reviews = list(pool.map(lambda _: store.record(actor(), document), range(12)))
    assert len({r.id for r in reviews}) == 1
    value = reviews[0]
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda _: store.approve(actor(), value.id, **args(value)), range(12)))
    assert len(set(results)) == 1
    with database() as db:
        assert db.execute(
            "SELECT count(*) FROM sky_state.migration_review_audit WHERE workspace=%s",
            (store.operations.workspace,),
        ).fetchone() == (2,)


def test_new_observation_invalidates_previous_approval_and_cannot_be_replaced_by_old_one(
    store, database, case
):
    first_report = report(case, database)
    first = store.record(actor(), first_report)
    store.approve(actor(), first.id, **args(first))
    current = store.record(actor(), report(case, database))
    assert current.id != first.id and current.approved_by is None
    with pytest.raises(MigrationReviewUnavailable):
        store.require(actor(), first.id, **args(first))
    with pytest.raises(MigrationReviewUnavailable):
        store.record(actor(), first_report)


def test_expired_evidence_cannot_be_approved(store, database, case):
    value = store.record(actor(), report(case, database, old_seconds=120))
    with pytest.raises(MigrationReviewUnavailable):
        store.approve(actor(), value.id, **args(value))


def test_new_failed_collection_invalidates_old_approval_without_storing_diagnostics(store, database, case):
    from domain.database_inventory import DatabaseInventoryUnavailable

    first = store.record(actor(), report(case, database))
    store.approve(actor(), first.id, **args(first))
    case[3][0].inspect.side_effect = DatabaseInventoryUnavailable("password=PRIVATE-CANARY")
    failed = report(case, database)
    current = store.record(actor(), failed)
    with pytest.raises(MigrationReviewUnavailable):
        store.require(actor(), first.id, **args(first))
    with pytest.raises(MigrationReviewUnavailable):
        store.approve(actor(), current.id, **args(current))
    with database() as db:
        value = db.execute(
            "SELECT report::text FROM sky_state.migration_preflight_reviews WHERE workspace=%s AND id=%s",
            (store.operations.workspace, current.id),
        ).fetchone()[0]
    assert "PRIVATE-CANARY" not in value


def test_later_finishing_review_cannot_overwrite_newer_source_observations(store, database, case):
    first_report = report(case, database)
    first = store.record(actor(), first_report)
    store.approve(actor(), first.id, **args(first))
    latest = report(case, database)
    reader = case[3][0]
    old_time = reader.inspect.return_value.observed_at - timedelta(seconds=5)
    reader.inspect.return_value = replace(
        reader.inspect.return_value,
        observed_at=old_time,
        resource=replace(reader.inspect.return_value.resource, observed_at=old_time),
    )
    from datetime import datetime

    now = datetime.fromisoformat(latest["preflight"]["observed_at"])
    overlapping = DatabaseMigrationPreflight(*case[3], clock=lambda: now, max_age_seconds=60).inspect(
        *case[:3],
        source_revision="a" * 64,
    )
    with pytest.raises(MigrationReviewUnavailable):
        store.record(actor(), overlapping)
    assert store.require(actor(), first.id, **args(first)).approved_by == "alice"


def test_approval_stops_being_usable_at_actual_database_deadline(store, database, case):
    value = store.record(actor(), report(case, database, max_age=2, old_seconds=0))
    store.approve(actor(), value.id, **args(value))
    with database() as db:
        now = db.execute("SELECT clock_timestamp()").fetchone()[0]
    time.sleep(max(0, (value.expires_at - now).total_seconds()) + 0.05)
    with pytest.raises(MigrationReviewUnavailable):
        store.require(actor(), value.id, **args(value))


@pytest.mark.parametrize("principal", [actor(Role.VIEWER), actor(org="foreign")])
def test_viewer_and_foreign_org_cannot_approve(store, database, case, principal):
    value = store.record(actor(), report(case, database))
    with pytest.raises((PermissionError, FileNotFoundError)):
        store.approve(principal, value.id, **args(value))


def test_changed_plan_or_evidence_and_revocation_block_reuse(store, database, case):
    value = store.record(actor(), report(case, database))
    store.approve(actor(), value.id, **args(value))
    for key, replacement in (("plan_id", "DBM-" + "b" * 64), ("evidence_id", "DBI-" + "b" * 64)):
        with pytest.raises(MigrationReviewUnavailable):
            store.require(actor(), value.id, **{**args(value), key: replacement})
    assert store.revoke(actor(), value.id) and not store.revoke(actor(), value.id)
    with pytest.raises(MigrationReviewUnavailable):
        store.require(actor(), value.id, **args(value))


def test_audit_failure_rolls_back_new_head_and_keeps_previous_approval(store, database, case):
    first = store.record(actor(), report(case, database))
    store.approve(actor(), first.id, **args(first))
    with patch.object(store, "_event", side_effect=OSError("audit unavailable")), pytest.raises(OSError):
        store.record(actor(), report(case, database))
    assert store.require(actor(), first.id, **args(first)).approved_by == "alice"


def test_unknown_application_is_not_adopted(store, database, case):
    source, target, safety, readers = case
    document = report(
        (
            replace(source, application_id="unknown"),
            replace(target, application_id="unknown"),
            safety,
            readers,
        ),
        database,
    )
    with pytest.raises(FileNotFoundError):
        store.record(actor(), document)


def test_native_vm_and_sql_observation_to_persisted_metadata_approval(database, databases):
    if not os.environ.get("SKY_TEST_VM_INVENTORY_REGISTRATION"):
        pytest.skip("Native pinned-SSH VM ownership registration required")
    from application.database_migration_reviews import DatabaseMigrationReviewService

    placements, readers, _ = databases
    store = PostgresMigrationReviews(
        PostgresDeploymentAdmission(
            PostgresOperationStore(database, workspace=uuid4().hex),
            account_id="111111111111",
            region="ap-northeast-2",
        )
    )
    principal = actor(org=placements[0].organization_id, user="operator")
    with database() as db:
        db.execute(
            "INSERT INTO sky_state.application_owners(workspace,application_id,organization_id,created_by) VALUES(%s,%s,%s,%s)",
            (
                store.operations.workspace,
                placements[0].application_id,
                principal.organization_id,
                principal.user_id,
            ),
        )
    preflight = DatabaseMigrationPreflight(*readers, clock=lambda: datetime.now(UTC), max_age_seconds=60)
    value = DatabaseMigrationReviewService(preflight, store).review(
        principal,
        *placements,
        MigrationSafetyPolicy(120, 600, 86400),
        source_revision="a" * 64,
    )
    approved = store.approve(principal, value.id, **args(value))
    assert not approved.execution_authorized
    with database() as db:
        document = db.execute(
            "SELECT report FROM sky_state.migration_preflight_reviews WHERE workspace=%s AND id=%s",
            (store.operations.workspace, value.id),
        ).fetchone()[0]
    assert all(
        inventory["resource"]["evidence_ref"].startswith("VM-")
        for inventory in document["preflight"]["inventories"].values()
    )
    assert document["blockers"] == ["route_not_implemented"]
