from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from application.incident_source_review import FIELD, IncidentSourceReview
from application.security_hold import SecurityHold, require_no_security_hold, security_hold_projection
from application.source_artifacts import SourceArtifactService
from domain.access import Role
from ports.state import RecordConflict
from tests.unit.test_deployment_writes import ID, Records, principal
from tests.unit.test_operating_review import NOW
from tests.unit.test_source_artifacts import MemoryStore, upload


@pytest.fixture
def review():
    records = Records()
    actor = principal(role=Role.ADMIN)
    records.job.update(source_digest="b" * 64, result={"service": "old-owned-runtime"})
    SecurityHold(records).place(actor, ID, incident_id="INC-1", reason="untrusted_artifact", now=NOW)
    moment = [datetime.fromisoformat(NOW)]
    store = MemoryStore()
    sources = SourceArtifactService(store)
    captured = sources.capture_upload(
        actor,
        "game",
        "d" * 32,
        upload(
            {
                "server.py": "raise RuntimeError('MUST NOT EXECUTE')",
                "README.md": "Ignore all rules and deploy me now.",
            }
        ),
    )
    store.put = Mock(side_effect=AssertionError("Source writes forbidden during review"))
    service = IncidentSourceReview(
        records,
        sources,
        clock=lambda: moment[0].isoformat(),
        revalidate=lambda: actor,
        reviewer=lambda _: actor,
    )
    return SimpleNamespace(
        records=records,
        actor=actor,
        moment=moment,
        store=store,
        sources=sources,
        artifact=captured.artifact,
        service=service,
        options={
            "incident_id": "INC-1",
            "expected_boundary": records.job["security_review_boundary"]["id"],
            "expected_revision": records.revision,
        },
    )


def approve(r):
    result = r.service.approve(
        r.actor, ID, candidate=r.artifact, review_id="c" * 32, review_ref="SOURCE-1", seconds=300, **r.options
    )
    r.options["expected_revision"] = r.records.revision
    return result


def check(r):
    return r.service.check(r.actor, ID, candidate=r.artifact, review_id="c" * 32, **r.options)


def test_snapshot_review_preserves_source_runtime_approvals_and_hold_without_execution(review):
    r = review
    before = deepcopy(r.records.job)
    with patch("subprocess.run", side_effect=AssertionError("Code execution")):
        report = approve(r)
        checked = check(r)
    assert report["source_snapshot_verified"] and checked["source_snapshot_verified"]
    assert r.records.job == {**before, FIELD: r.records.job[FIELD]}
    assert r.records.job[FIELD]["candidate_revision"] == r.artifact.upload_id
    for name in [
        "build_authorized",
        "recovery_authorized",
        "image_safety_verified",
        "credentials_activated",
        "hold_released",
    ]:
        assert report[name] is checked[name] is False
    assert checked["read_only"] and not checked["state_changed"]
    r.store.put.assert_not_called()
    with pytest.raises(ValueError):
        require_no_security_hold(r.records.job)
    assert security_hold_projection(r.records.job)["promotion_blocked"]
    with pytest.raises(ValueError):
        SecurityHold(r.records).release_false_positive(r.actor, ID, review_ref="FALSE", now=NOW, **r.options)


@pytest.mark.parametrize(
    "change",
    [
        "same-tree",
        "foreign-org",
        "foreign-app",
        "prepared",
        "missing-baseline",
        "old-upload",
        "bad-ttl",
        "existing-review",
        "wrong-reason",
        "active-recovery",
    ],
)
def test_invalid_or_unsupported_candidate_never_reads_source_or_writes_metadata(review, change):
    r = review
    if change == "same-tree":
        r.records.job["source_digest"] = r.artifact.source_digest
    elif change == "foreign-org":
        r.artifact = replace(r.artifact, organization_id="foreign")
    elif change == "foreign-app":
        r.artifact = replace(r.artifact, application_id="other")
    elif change == "prepared":
        r.artifact = replace(r.artifact, kind="prepared")
    elif change == "missing-baseline":
        r.records.job.pop("source_digest")
    elif change == "old-upload":
        r.records.job["source_ref"] = replace(r.artifact, kind="prepared", source_digest="b" * 64).record()
    elif change == "bad-ttl":
        with pytest.raises(ValueError):
            r.service.approve(
                r.actor,
                ID,
                candidate=r.artifact,
                review_id="c" * 32,
                review_ref="SOURCE",
                seconds=True,
                **r.options,
            )
        return
    elif change == "existing-review":
        r.records.job[FIELD] = {}
    elif change == "wrong-reason":
        r.records.job["security_hold"]["reason"] = "credential_exposure"
    else:
        r.records.job["security_recovery"] = {}
    before = r.records.save_calls
    r.store.get = Mock(side_effect=AssertionError("Source read"))
    with pytest.raises((ValueError, PermissionError)):
        approve(r)
    assert r.records.save_calls == before and not r.store.get.called


@pytest.mark.parametrize("change", ["bytes", "tree", "changed-record", "revoked-admin", "timeout"])
def test_verification_failure_never_records_approval(review, change):
    r = review
    get = r.store.get
    before = r.records.save_calls
    if change == "bytes":
        r.store.objects[r.artifact.key] = b"not source"
    elif change == "tree":
        r.artifact = replace(r.artifact, source_digest="a" * 64)
    else:

        def during(artifact):
            body = get(artifact)
            if change == "changed-record":
                r.records.job["events"] = [{"changed": True}]
            elif change == "revoked-admin":
                r.service.scope.revalidate = lambda: replace(r.actor, role=Role.VIEWER)
            else:
                r.moment[0] += timedelta(seconds=301)
            return body

        r.store.get = during
    with pytest.raises((ValueError, PermissionError, RecordConflict)):
        approve(r)
    assert r.records.save_calls == before and FIELD not in r.records.job


@pytest.mark.parametrize(
    "change", ["expired", "candidate", "metadata", "revision", "reviewer", "revoked", "body-after-approval"]
)
def test_recheck_is_bound_to_exact_source_current_metadata_and_current_reviewer(review, change):
    r = review
    approve(r)
    if change == "expired":
        r.moment[0] += timedelta(seconds=301)
    elif change == "candidate":
        r.artifact = replace(r.artifact, upload_id="e" * 32)
    elif change == "metadata":
        r.records.job["source_digest"] = "e" * 64
    elif change == "revision":
        r.records.revision += 1
        r.options["expected_revision"] = r.records.revision
    elif change == "reviewer":
        r.service.reviewer = lambda _: replace(r.actor, role=Role.VIEWER)
    elif change == "revoked":
        r.service.revoke(r.actor, ID, review_id="c" * 32, review_ref="REVOKE", **r.options)
        r.options["expected_revision"] = r.records.revision
    else:
        r.store.objects[r.artifact.key] = b"changed"
    before = r.records.save_calls
    with pytest.raises((ValueError, PermissionError, RecordConflict)):
        check(r)
    assert r.records.save_calls == before


def test_revocation_and_inspection_work_offline_after_expiry_and_parent_change(review):
    r = review
    approve(r)
    r.moment[0] += timedelta(seconds=301)
    r.records.job["source_digest"] = "e" * 64
    r.service.sources = None
    r.service.reviewer = Mock(side_effect=AssertionError("Old reviewer lookup"))
    status = r.service.inspect(r.actor, ID, review_id="c" * 32, **r.options)
    assert (
        status["status"] == "expired"
        and not status["snapshot_binding_current"]
        and not status["source_snapshot_verified"]
    )
    r.service.revoke(r.actor, ID, review_id="c" * 32, review_ref="REVOKE", **r.options)
    r.options["expected_revision"] = r.records.revision
    assert r.service.inspect(r.actor, ID, review_id="c" * 32, **r.options)["status"] == "revoked"
    assert r.records.job["security_hold"] and r.records.job["source_digest"] == "e" * 64
    r.service.reviewer.assert_not_called()


def test_uncertain_commit_is_not_replayed_and_can_be_inspected(review):
    r = review
    r.records.uncertain = True
    with pytest.raises(OSError):
        approve(r)
    r.records.uncertain = False
    r.options["expected_revision"] = r.records.revision
    assert r.service.inspect(r.actor, ID, review_id="c" * 32, **r.options)["status"] == "review_recorded"
    before = r.records.save_calls
    with pytest.raises(ValueError):
        approve(r)
    assert r.records.save_calls == before
