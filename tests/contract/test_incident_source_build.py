"""Independent source build approval ledger against disposable PostgreSQL."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import pytest

from adapters.state.source_build_approvals import PostgresSourceBuildApprovals
from application.incident_source_build import IncidentSourceBuildApproval
from domain.access import Role
from ports.remote_builds import BuildSettings
from ports.state import RecordConflict
from tests.contract.test_incident_source_review import attach
from tests.contract.test_operation_store import count
from tests.contract.test_operation_store import database as database  # noqa: PLC0414
from tests.contract.test_operation_store import store as store  # noqa: PLC0414
from tests.unit.test_deployment_writes import ID, principal
from tests.unit.test_incident_source_build import APPROVAL, BUILD, consent
from tests.unit.test_incident_source_review import review as review  # noqa: PLC0414


@pytest.fixture
def build(review, store):
    r = attach(review, store)
    r.moment[0] = datetime.now(UTC)
    receipt = r.service.approve(
        r.actor, ID, candidate=r.artifact, review_id="c" * 32, review_ref="SOURCE-1", seconds=300, **r.options
    )
    r.options["expected_revision"] = receipt["metadata_revision"]
    c = SimpleNamespace(
        r=r,
        settings=BuildSettings(
            "owner/builder", "main", "1" * 40, "2" * 40, "source-bucket", "111111111111", "ap-northeast-2"
        ),
    )
    ledger = PostgresSourceBuildApprovals(store.records, revalidate=lambda: r.actor)
    ledger.initialize()
    c.ledger = ledger
    c.service = IncidentSourceBuildApproval(
        r.service, ledger, c.settings, clock=lambda: datetime.now(UTC).isoformat(), reviewer=lambda _: r.actor
    )
    return c


def test_consent_leaves_job_source_revision_and_operations_unchanged(build, store, database):
    c = build
    before = store.records.load_job(ID)
    report = consent(c)
    assert report["build_consent_recorded"] and not report["execution_authorized"]
    assert c.service.check(c.r.actor, ID, approval_id=APPROVAL, **c.r.options)["read_only"]
    assert store.records.load_job(ID) == before
    assert count(store, database, "operations") == count(store, database, "outbox_events") == 0
    c.ledger.initialize()
    assert c.ledger.load(c.r.actor, APPROVAL)["build_id"] == BUILD


def test_concurrent_approvals_for_one_review_create_one_record(build, store, database):
    c = build

    def run(index):
        try:
            return c.service.approve(
                c.r.actor,
                ID,
                review_id="c" * 32,
                approval_id=str(index + 1) * 32,
                build_id=str(uuid4()),
                review_ref="BUILD-1",
                seconds=300,
                **c.r.options,
            )
        except RecordConflict:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, range(2)))
    assert sum(x is not None for x in results) == 1
    with database() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM sky_state.source_build_approvals WHERE workspace=%s", (store.workspace,)
            ).fetchone()[0]
            == 1
        )


def test_job_change_between_verification_and_locked_write_creates_no_consent(build, store):
    c = build
    original = c.ledger.create

    def changed(actor, approval, snapshot):
        store.records.save_job(ID, {**snapshot.record, "changed": True}, expected_revision=snapshot.revision)
        return original(actor, approval, snapshot)

    with patch.object(c.ledger, "create", side_effect=changed), pytest.raises(RecordConflict):
        consent(c)
    with pytest.raises(FileNotFoundError):
        c.ledger.load(c.r.actor, APPROVAL)


def test_offline_revoke_preserves_job_and_refuses_repeated_revocation(build, store):
    c = build
    consent(c)
    before = store.records.load_job(ID)
    c.r.service.sources = None
    result = c.service.revoke(c.r.actor, ID, approval_id=APPROVAL, review_ref="REVOKE-1", **c.r.options)
    assert result["status"] == "revoked"
    assert store.records.load_job(ID) == before
    with pytest.raises(ValueError):
        c.service.revoke(c.r.actor, ID, approval_id=APPROVAL, review_ref="REPLAY", **c.r.options)
    with pytest.raises(ValueError):
        c.service.check(c.r.actor, ID, approval_id=APPROVAL, **c.r.options)


def test_lost_commit_acknowledgement_is_inspectable_without_second_record(build, store):
    c = build
    connection = store.records._connection

    @contextmanager
    def lost():
        with connection() as db:
            yield db
        raise OSError("Commit acknowledgement lost")

    original = c.ledger.create

    def create(actor, approval, snapshot):
        with patch.object(store.records, "_connection", lost):
            return original(actor, approval, snapshot)

    with patch.object(c.ledger, "create", side_effect=create), pytest.raises(OSError):
        consent(c)
    assert c.service.inspect(c.r.actor, ID, approval_id=APPROVAL, **c.r.options)["status"] == "approved"
    with pytest.raises(RecordConflict):
        consent(c)


def test_foreign_organization_and_demoted_admin_cannot_read_consent(build):
    c = build
    consent(c)
    other = principal(org="foreign", role=Role.ADMIN)
    c.ledger.revalidate = lambda: other
    with pytest.raises(FileNotFoundError):
        c.ledger.load(other, APPROVAL)
    c.ledger.revalidate = lambda: principal(role=Role.VIEWER)
    with pytest.raises(PermissionError):
        c.ledger.load(c.r.actor, APPROVAL)


def test_expiry_at_insert_time_cannot_be_bypassed_by_slow_admin_check(build):
    import time

    c = build
    calls = []

    def delayed_admin():
        calls.append(True)
        if len(calls) == 2:
            time.sleep(1.1)
        return c.r.actor

    c.ledger.revalidate = delayed_admin
    with pytest.raises((ValueError, RecordConflict)):
        c.service.approve(
            c.r.actor,
            ID,
            review_id="c" * 32,
            approval_id=APPROVAL,
            build_id=BUILD,
            review_ref="SHORT-LIVED",
            seconds=1,
            **c.r.options,
        )
    with pytest.raises(FileNotFoundError):
        c.ledger.load(c.r.actor, APPROVAL)
