"""Actual PostgreSQL session exclusion, closure and loss; no AWS calls."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event
from uuid import uuid4

import pytest

from adapters.state.operating_review_lock import PostgresOperatingReviewLocks
from tests.contract.test_operation_store import database as database  # noqa: PLC0414

pytest_plugins = ["tests.unit.test_operating_review"]


def test_other_session_cannot_collect_same_application(database):
    workspace = uuid4().hex
    locks = PostgresOperatingReviewLocks(database, workspace=workspace)

    def competing():
        with locks.acquire("org1", "game") as guard:
            return guard is None

    with locks.acquire("org1", "game") as guard, ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(competing).result(timeout=5) is True
        guard()
    with locks.acquire("org1", "game") as guard:
        assert guard is not None
        guard()


@pytest.mark.parametrize("different", ["workspace", "organization", "application"])
def test_scope_is_independent(database, different):
    workspace = uuid4().hex
    first = PostgresOperatingReviewLocks(database, workspace=workspace)
    second = PostgresOperatingReviewLocks(
        database, workspace=uuid4().hex if different == "workspace" else workspace
    )
    with (
        first.acquire("org1", "game"),
        second.acquire(
            "org2" if different == "organization" else "org1",
            "other" if different == "application" else "game",
        ) as guard,
    ):
        assert guard is not None
        guard()


def test_exception_releases_session_lock(database):
    locks = PostgresOperatingReviewLocks(database, workspace=uuid4().hex)
    with pytest.raises(RuntimeError), locks.acquire("org1", "game"):
        raise RuntimeError("failed collection")
    with locks.acquire("org1", "game") as guard:
        assert guard is not None
        guard()


def test_terminated_session_loses_guard_and_allows_fresh_owner(database):
    opened = []

    def connect():
        connection = database()
        opened.append(connection)
        return connection

    locks = PostgresOperatingReviewLocks(connect, workspace=uuid4().hex)
    with locks.acquire("org1", "game") as stale:
        pid = opened[0].info.backend_pid
        with database() as admin:
            assert admin.execute("SELECT pg_terminate_backend(%s)", (pid,)).fetchone() == (True,)
        with pytest.raises(OSError):
            stale()
        with locks.acquire("org1", "game") as fresh:
            assert fresh is not None
            fresh()


def test_concurrent_controllers_collect_once_while_review_is_owned(database, operating_review_setup):
    from adapters.state.postgres import PostgresDeploymentRecordStore
    from application.operating_review import OperatingReview
    from interfaces.operating_review import OperatingReviewController
    from tests.unit.test_deployment_writes import principal
    from tests.unit.test_operating_review import ID, NOW
    from tests.unit.test_promotion_policy import policy_with_criteria, samples

    fake, policy, _ = operating_review_setup
    policy = policy_with_criteria(policy)
    samples(fake)
    workspace = uuid4().hex
    records = PostgresDeploymentRecordStore(database, workspace=workspace)
    records.save_job(ID, fake.job, expected_revision=None)
    records.save_health(ID, fake.health, expected_revision=None)
    OperatingReview(records).grant_automation(
        principal(),
        ID,
        policy,
        max_incremental_monthly_cents=3000,
        expires_at="2026-10-12T00:00:00+00:00",
        now=NOW,
    )
    locks = PostgresOperatingReviewLocks(database, workspace=workspace)
    entered, release = Event(), Event()
    collections = []

    def collect(*_):
        collections.append(True)
        entered.set()
        assert release.wait(timeout=10)

    def tick():
        controller = OperatingReviewController(records, {ID: policy}, clock=lambda: NOW)
        return controller.review_automations_once(
            lambda *_: principal(),
            collect=collect,
            coordinate=locks.acquire,
        )

    with ThreadPoolExecutor(max_workers=1) as pool:
        running = pool.submit(tick)
        try:
            assert entered.wait(timeout=5)
            assert tick() == [{"job_id": ID, "status": "review_in_progress"}]
        finally:
            release.set()
        assert running.result(timeout=10)[0]["status"] == "approved"
    assert collections == [True]
    assert records.load_job(ID).record["operating_proposal"]["status"] == "approved"
