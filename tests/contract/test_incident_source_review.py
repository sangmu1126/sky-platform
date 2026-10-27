"""Source review CAS and old-recovery rejection on actual PostgreSQL."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import timedelta
from threading import Barrier
from unittest.mock import patch

import pytest

from application.incident_source_review import FIELD, HISTORY, IncidentSourceReview
from ports.state import RecordConflict
from tests.contract.test_incident_execution_fence import incident as incident  # noqa: PLC0414
from tests.contract.test_incident_recovery_completion import verified
from tests.contract.test_operation_store import count
from tests.contract.test_operation_store import database as database  # noqa: PLC0414
from tests.contract.test_operation_store import store as store  # noqa: PLC0414
from tests.unit.test_deployment_writes import ID
from tests.unit.test_incident_source_review import approve, check
from tests.unit.test_incident_source_review import review as review  # noqa: PLC0414


def attach(review, store):
    r = review
    revision = store.records.save_job(ID, deepcopy(r.records.job))
    r.records = store.records
    r.options["expected_revision"] = revision
    r.service = IncidentSourceReview(
        store.records,
        r.sources,
        clock=lambda: r.moment[0].isoformat(),
        revalidate=lambda: r.actor,
        reviewer=lambda _: r.actor,
    )
    return r


def test_review_and_check_persist_without_operations_or_outbox(review, store, database):
    r = attach(review, store)
    before = store.records.load_job(ID)
    report = r.service.approve(
        r.actor, ID, candidate=r.artifact, review_id="c" * 32, review_ref="REVIEW-1", seconds=300, **r.options
    )
    r.options["expected_revision"] = report["metadata_revision"]
    assert check(r)["source_snapshot_verified"]
    after = store.records.load_job(ID)
    assert after.record == {**before.record, FIELD: after.record[FIELD]}
    assert all(
        count(store, database, table) == 0 for table in ["operations", "outbox_events", "operation_events"]
    )


def test_concurrent_review_approvals_cannot_overwrite_each_other(review, store):
    r = attach(review, store)
    original = store.records.save_job
    barrier = Barrier(2)

    def saving(*args, **kwargs):
        barrier.wait(timeout=10)
        return original(*args, **kwargs)

    def run(index):
        try:
            return r.service.approve(
                r.actor,
                ID,
                candidate=r.artifact,
                review_id=str(index + 1) * 32,
                review_ref="REVIEW-1",
                seconds=300,
                **r.options,
            )
        except RecordConflict:
            return None

    with (
        patch.object(store.records, "save_job", side_effect=saving),
        ThreadPoolExecutor(max_workers=2) as pool,
    ):
        reports = list(pool.map(run, range(2)))
    assert sum(report is not None for report in reports) == 1
    assert store.records.load_job(ID).revision == r.options["expected_revision"] + 1


def test_commit_then_lost_acknowledgement_can_only_be_inspected(review, store):
    r = attach(review, store)
    original = store.records.save_job

    def lost(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("Acknowledgement lost")

    with patch.object(store.records, "save_job", side_effect=lost), pytest.raises(OSError):
        approve(r)
    r.options["expected_revision"] = store.records.load_job(ID).revision
    report = r.service.inspect(r.actor, ID, review_id="c" * 32, **r.options)
    assert report["read_only"] and not report["hold_released"]
    with pytest.raises(ValueError):
        approve(r)


@pytest.mark.parametrize("record", [{}, False, {"revoked_at": "2026-10-27T00:00:00+00:00"}])
@pytest.mark.parametrize("field", [FIELD, HISTORY])
def test_old_recovery_completion_never_consumes_source_review(store, incident, record, field):
    actor, options, _op, _lease, _result, service = verified(store, incident)
    snapshot = store.records.load_job(ID)
    options["expected_revision"] = store.records.save_job(
        ID, {**snapshot.record, field: record}, expected_revision=snapshot.revision
    )
    before = store.records.load_job(ID)
    with pytest.raises(ValueError):
        service.complete_recovery(actor, ID, recovery_id="f" * 32, **options)
    assert store.records.load_job(ID) == before


def prepare_successor(review, store):
    r = attach(review, store)
    report = r.service.approve(
        r.actor, ID, candidate=r.artifact, review_id="c" * 32, review_ref="ROOT", seconds=300, **r.options
    )
    r.options["expected_revision"] = report["metadata_revision"]
    r.moment[0] += timedelta(seconds=300)
    return r


def test_concurrent_successors_archive_predecessor_exactly_once(review, store, database):
    r = prepare_successor(review, store)
    original = store.records.save_job
    barrier = Barrier(2)

    def saving(*args, **kwargs):
        barrier.wait(timeout=10)
        return original(*args, **kwargs)

    def run(index):
        try:
            return r.service.supersede(
                r.actor,
                ID,
                candidate=r.artifact,
                review_id=str(index + 1) * 32,
                predecessor_review_id="c" * 32,
                review_ref="SUCCESSOR",
                seconds=300,
                **r.options,
            )
        except RecordConflict:
            return None

    with (
        patch.object(store.records, "save_job", side_effect=saving),
        ThreadPoolExecutor(max_workers=2) as pool,
    ):
        results = list(pool.map(run, range(2)))
    assert sum(result is not None for result in results) == 1
    snapshot = store.records.load_job(ID)
    assert len(snapshot.record[HISTORY]) == 1 and snapshot.record[HISTORY][0]["id"] == "c" * 32
    r.options["expected_revision"] = snapshot.revision
    assert r.service.check(
        r.actor, ID, candidate=r.artifact, review_id=snapshot.record[FIELD]["id"], **r.options
    )["source_snapshot_verified"]
    assert count(store, database, "operations") == count(store, database, "outbox_events") == 0


def test_failed_atomic_successor_save_keeps_original_review_and_history(review, store):
    r = prepare_successor(review, store)
    before = store.records.load_job(ID)
    with (
        patch.object(store.records, "save_job", side_effect=OSError("DB write failed")),
        pytest.raises(OSError),
    ):
        r.service.supersede(
            r.actor,
            ID,
            candidate=r.artifact,
            review_id="e" * 32,
            predecessor_review_id="c" * 32,
            review_ref="SUCCESSOR",
            seconds=300,
            **r.options,
        )
    assert store.records.load_job(ID) == before


def test_successor_committed_before_lost_ack_is_inspectable_without_replay(review, store):
    r = prepare_successor(review, store)
    original = store.records.save_job

    def lost(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("Acknowledgement lost")

    args = {
        "candidate": r.artifact,
        "review_id": "e" * 32,
        "predecessor_review_id": "c" * 32,
        "review_ref": "SUCCESSOR",
        "seconds": 300,
    }
    with patch.object(store.records, "save_job", side_effect=lost), pytest.raises(OSError):
        r.service.supersede(r.actor, ID, **args, **r.options)
    snapshot = store.records.load_job(ID)
    r.options["expected_revision"] = snapshot.revision
    report = r.service.inspect(r.actor, ID, review_id="e" * 32, **r.options)
    assert report["history_count"] == 1 and report["read_only"]
    with pytest.raises(ValueError):
        r.service.supersede(r.actor, ID, **args, **r.options)
    assert store.records.load_job(ID) == snapshot
