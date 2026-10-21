"""Session ownership and the controller guard are separate from resource execution."""

from contextlib import contextmanager
from unittest.mock import Mock

import psycopg
import pytest

from adapters.state.operating_review_lock import PostgresOperatingReviewLocks
from tests.unit.test_deployment_writes import principal

pytest_plugins = ["tests.unit.test_operating_automation_authorization"]


@pytest.fixture
def session():
    connection = Mock(closed=False)
    connection.execute.return_value.fetchone.side_effect = [(True,), (1,), (True,)]
    closed = []

    def close():
        closed.append(True)
        connection.closed = True

    connection.close.side_effect = close
    return connection, closed, PostgresOperatingReviewLocks(lambda: connection)


def test_session_guard_lifetime_and_release(session):
    connection, closed, locks = session
    with locks.acquire("org1", "game") as guard:
        guard()
        assert not closed
    assert closed == [True] and connection.autocommit is True
    assert "pg_advisory_unlock" in connection.execute.call_args.args[0]
    with pytest.raises(OSError, match="no longer held"):
        guard()


def test_busy_session_is_not_unlocked_by_non_owner(session):
    connection, closed, locks = session
    connection.execute.return_value.fetchone.side_effect = [(False,)]
    with locks.acquire("org1", "game") as guard:
        assert guard is None
    assert closed == [True] and connection.execute.call_count == 1


def test_session_error_is_sanitized_and_cannot_be_renewed(session):
    connection, closed, locks = session
    connection.execute.side_effect = [
        Mock(fetchone=Mock(return_value=(True,))),
        psycopg.OperationalError("private-password"),
        psycopg.OperationalError("private-password"),
    ]
    with pytest.raises(OSError) as error, locks.acquire("org1", "game") as guard:
        guard()
    assert "private-password" not in str(error.value)
    assert closed == [True]


def test_body_error_preserved_when_unlock_also_fails(session):
    connection, closed, locks = session
    connection.execute.side_effect = [
        Mock(fetchone=Mock(return_value=(True,))),
        psycopg.OperationalError("unlock failure"),
    ]
    with pytest.raises(RuntimeError, match="original"), locks.acquire("org1", "game"):
        raise RuntimeError("original")
    assert closed == [True]


@pytest.mark.parametrize("org,app", [("../org", "game"), ("org1", ""), ("org1", "a" * 129)])
def test_invalid_scope_does_not_open_a_connection(org, app):
    connect = Mock()
    with pytest.raises(ValueError), PostgresOperatingReviewLocks(connect).acquire(org, app):
        pass
    connect.assert_not_called()


def test_busy_timer_skips_collection_and_review(authorized):
    records, _, _, _, controller = authorized
    calls = []

    @contextmanager
    def coordinate(org, app):
        calls.append((org, app))
        yield None

    collect = Mock()
    report = controller.review_automations_once(
        Mock(return_value=principal()), collect=collect, coordinate=coordinate
    )
    assert report == [{"job_id": "a" * 16, "status": "review_in_progress"}]
    assert calls == [("org1", "game")]
    collect.assert_not_called()
    assert records.save_calls == 0


@pytest.mark.parametrize(
    "failure", ["lost_after_collection", "collection_error", "revoked_before_collection"]
)
def test_timer_releases_guard_and_never_approves_failed_pass(authorized, failure):
    records, _, service, _, controller = authorized
    released = []
    guard = Mock(side_effect=[None, OSError("lock lost")]) if failure == "lost_after_collection" else Mock()

    @contextmanager
    def coordinate(*_):
        if failure == "revoked_before_collection":
            service.revoke_automation(principal(), "a" * 16)
        try:
            yield guard
        finally:
            released.append(True)

    collect = Mock(side_effect=OSError("collector failed")) if failure == "collection_error" else Mock()
    report = controller.review_automations_once(
        Mock(return_value=principal()), collect=collect, coordinate=coordinate
    )
    assert report[0]["status"] == "review_blocked"
    assert released == [True] and "operating_proposal" not in records.job
    if failure == "revoked_before_collection":
        collect.assert_not_called()


def test_unlock_failure_does_not_report_both_approval_and_failure(authorized):
    records, _, _, _, controller = authorized

    @contextmanager
    def coordinate(*_):
        yield lambda: None
        raise OSError("release uncertain")

    report = controller.review_automations_once(Mock(return_value=principal()), coordinate=coordinate)
    assert report == [{"job_id": "a" * 16, "status": "review_blocked"}]
    # A cleanup failure cannot roll back an already committed metadata write.
    assert records.job["operating_proposal"]["status"] == "approved"
