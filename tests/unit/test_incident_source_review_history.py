from copy import deepcopy
from datetime import timedelta
from unittest.mock import Mock

import pytest

from application.incident_source_review import FIELD, HISTORY, MAX_HISTORY
from application.security_hold import SecurityHold, require_no_security_hold, security_hold_projection
from ports.state import RecordConflict
from tests.unit.test_deployment_writes import ID
from tests.unit.test_incident_source_review import approve
from tests.unit.test_incident_source_review import review as review  # noqa: PLC0414


def successor(r, *, review_id="e" * 32, predecessor="c" * 32):
    result = r.service.supersede(
        r.actor,
        ID,
        predecessor_review_id=predecessor,
        candidate=r.artifact,
        review_id=review_id,
        review_ref="SUCCESSOR-1",
        seconds=300,
        **r.options,
    )
    r.options["expected_revision"] = result["metadata_revision"]
    return result


def terminate(r, kind="expired"):
    approve(r)
    if kind == "revoked":
        result = r.service.revoke(r.actor, ID, review_id="c" * 32, review_ref="REVOKE-1", **r.options)
        r.options["expected_revision"] = result["metadata_revision"]
    else:
        r.moment[0] += timedelta(seconds=300)


@pytest.mark.parametrize("kind", ["revoked", "expired"])
def test_successor_preserves_previous_review_and_held_parent(review, kind):
    r = review
    terminate(r, kind)
    parent = deepcopy(r.records.job)
    old = deepcopy(parent[FIELD])
    report = successor(r)
    assert r.records.job[HISTORY] == [old]
    assert r.records.job == {**parent, HISTORY: [old], FIELD: r.records.job[FIELD]}
    assert r.records.job[FIELD]["version"] == 2
    assert r.records.job[FIELD]["supersedes_review_id"] == old["id"]
    assert not report["build_authorized"] and not report["hold_released"]
    checked = r.service.check(r.actor, ID, candidate=r.artifact, review_id="e" * 32, **r.options)
    assert checked["source_snapshot_verified"]
    with pytest.raises(ValueError):
        r.service.check(r.actor, ID, candidate=r.artifact, review_id="c" * 32, **r.options)
    assert r.service.inspect(r.actor, ID, review_id="e" * 32, **r.options)["history_count"] == 1


@pytest.mark.parametrize("change", ["active", "wrong-predecessor", "reuse-id", "bad-id", "future-revocation"])
def test_invalid_supersession_never_reads_or_writes(review, change):
    r = review
    terminate(r, "revoked" if change == "future-revocation" else "expired")
    if change == "active":
        r.moment[0] -= timedelta(seconds=299)
    if change == "future-revocation":
        r.records.job[FIELD]["revoked_at"] = (r.moment[0] + timedelta(seconds=1)).isoformat()
    r.service.sources.restore = Mock(side_effect=AssertionError("Source read"))
    before = deepcopy(r.records.job)
    saves = r.records.save_calls
    with pytest.raises(ValueError):
        successor(
            r,
            review_id="c" * 32 if change == "reuse-id" else ("bad" if change == "bad-id" else "e" * 32),
            predecessor="f" * 32 if change == "wrong-predecessor" else "c" * 32,
        )
    assert r.records.job == before and r.records.save_calls == saves


@pytest.mark.parametrize(
    "change",
    ["delete", "empty", "reorder", "duplicate", "foreign", "digest", "predecessor", "active-ancestor"],
)
def test_history_corruption_rejected_even_for_metadata_inspection(review, change):
    r = review
    terminate(r)
    successor(r)
    r.moment[0] += timedelta(seconds=300)
    successor(r, review_id="f" * 32, predecessor="e" * 32)
    if change == "delete":
        del r.records.job[HISTORY]
    elif change == "empty":
        r.records.job[HISTORY] = []
    elif change == "reorder":
        r.records.job[HISTORY].reverse()
    elif change == "duplicate":
        r.records.job[HISTORY][1] = deepcopy(r.records.job[HISTORY][0])
    elif change == "foreign":
        r.records.job[HISTORY][0]["candidate"]["organization_id"] = "foreign"
    elif change == "digest":
        r.records.job[FIELD]["history_digest"] = "0" * 64
    elif change == "predecessor":
        r.records.job[FIELD]["supersedes_review_id"] = "0" * 32
    else:
        r.records.job[HISTORY][0]["expires_at"] = (r.moment[0] + timedelta(seconds=1)).isoformat()
    saves = r.records.save_calls
    with pytest.raises((ValueError, PermissionError)):
        r.service.inspect(r.actor, ID, review_id="f" * 32, **r.options)
    assert r.records.save_calls == saves


def test_history_capacity_never_discards_or_reuses_prior_reviews(review):
    r = review
    approve(r)
    previous = "c" * 32
    for index in range(MAX_HISTORY):
        r.moment[0] += timedelta(seconds=300)
        current = f"{index:032x}"
        successor(r, review_id=current, predecessor=previous)
        previous = current
    assert len(r.records.job[HISTORY]) == MAX_HISTORY
    r.moment[0] += timedelta(seconds=300)
    before = deepcopy(r.records.job)
    with pytest.raises(ValueError, match="capacity"):
        successor(r, predecessor=previous)
    assert r.records.job == before


def test_lost_successor_ack_requires_inspection_not_replay(review):
    r = review
    terminate(r)
    r.records.uncertain = True
    with pytest.raises(OSError):
        successor(r)
    r.records.uncertain = False
    r.options["expected_revision"] = r.records.revision
    assert r.service.inspect(r.actor, ID, review_id="e" * 32, **r.options)["history_count"] == 1
    with pytest.raises(ValueError):
        successor(r)
    assert len(r.records.job[HISTORY]) == 1


def test_mid_verification_metadata_change_cannot_archive_predecessor(review):
    r = review
    terminate(r)
    original = r.store.get

    def changed(artifact):
        data = original(artifact)
        r.records.revision += 1
        return data

    r.store.get = changed
    with pytest.raises(RecordConflict):
        successor(r)
    assert HISTORY not in r.records.job and r.records.job[FIELD]["id"] == "c" * 32


@pytest.mark.parametrize("value", [False, [], {}, [{"unexpected": True}]])
def test_orphan_or_corrupt_history_cannot_reopen_old_paths(review, value):
    r = review
    r.records.job[HISTORY] = value
    assert security_hold_projection(r.records.job)["promotion_blocked"]
    with pytest.raises(ValueError):
        require_no_security_hold(r.records.job)
    with pytest.raises(ValueError):
        SecurityHold(r.records).release_false_positive(
            r.actor, ID, review_ref="RELEASE", now=r.moment[0].isoformat(), **r.options
        )
    with pytest.raises(ValueError):
        approve(r)


def test_successor_rehashes_source_and_keeps_predecessor_on_tamper(review):
    r = review
    terminate(r)
    before = deepcopy(r.records.job)
    r.store.objects[r.artifact.key] = b"tampered"
    with pytest.raises(ValueError):
        successor(r)
    assert r.records.job == before


def test_successor_revocation_preserves_chain_without_source_or_old_reviewer(review):
    r = review
    terminate(r)
    successor(r)
    before = deepcopy(r.records.job[HISTORY])
    r.service.sources = None
    r.service.reviewer = Mock(side_effect=AssertionError("Old reviewer lookup"))
    receipt = r.service.revoke(r.actor, ID, review_id="e" * 32, review_ref="REVOKE-SUCCESSOR", **r.options)
    r.options["expected_revision"] = receipt["metadata_revision"]
    report = r.service.inspect(r.actor, ID, review_id="e" * 32, **r.options)
    assert report["status"] == "revoked" and report["history_count"] == 1
    assert r.records.job[HISTORY] == before
    assert r.records.job["security_hold"]["reason"] == "untrusted_artifact"
