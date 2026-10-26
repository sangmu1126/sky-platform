from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from application.incident_artifact_review import FIELD, HISTORY, IncidentArtifactReview
from application.security_hold import SecurityHold, require_no_security_hold
from domain.access import Role
from ports.state import RecordConflict
from tests.unit.test_deployment_writes import Records, principal
from tests.unit.test_incident_runtime_inspection import fixture
from tests.unit.test_operating_review import ID, NOW
from tests.unit.test_recovery_image_inspection import registration


@pytest.fixture
def context():
    records, actor = Records(), principal(role=Role.ADMIN)
    records.job.update(result=fixture()[0], source_digest="b" * 64)
    SecurityHold(records).place(actor, ID, incident_id="INC-1", reason="untrusted_artifact", now=NOW)
    moment = [datetime.fromisoformat(NOW)]
    inspector = Mock()
    inspector.image_registration = registration(
        application_id="game", boundary_id=records.job["security_review_boundary"]["id"]
    )

    def inspect(*_, **options):
        return {
            **dict.fromkeys(
                (
                    "signature_verified",
                    "expected_input_binding_matched",
                    "consumed_deployment_approval_matched",
                    "key_liveness_checked",
                    "ecr_image_verified",
                    "image_signature_approval_binding_matched",
                    "read_only",
                ),
                True,
            ),
            **dict.fromkeys(
                (
                    "recovery_authorized",
                    "current_approval_verified",
                    "faithful_compilation_verified",
                    "image_safety_verified",
                    "state_changed",
                ),
                False,
            ),
            "incident_id": "INC-1",
            "boundary_id": records.job["security_review_boundary"]["id"],
            "metadata_revision": options["expected_revision"],
            "observed_at": moment[0].isoformat(),
            "expires_at": (moment[0] + timedelta(seconds=300)).isoformat(),
            "build_id": "12345678-1234-1234-1234-123456789abc",
            "request_digest": "f" * 64,
            "key_arn": "arn:aws:kms:ap-northeast-2:111111111111:key/12345678-1234-1234-1234-123456789abc",
            "public_key_fingerprint": "sha256:" + "c" * 64,
        }

    inspector.inspect.side_effect = inspect
    service = IncidentArtifactReview(
        records,
        inspector,
        clock=lambda: moment[0].isoformat(),
        revalidate=lambda: actor,
        reviewer=lambda _: actor,
    )
    options = {
        "incident_id": "INC-1",
        "expected_boundary": records.job["security_review_boundary"]["id"],
        "expected_revision": records.revision,
    }
    return SimpleNamespace(
        records=records, actor=actor, service=service, inspector=inspector, options=options, moment=moment
    )


def approve(c, **changes):
    return c.service.approve(c.actor, ID, review_id="c" * 32, review_ref="REVIEW-1", **(c.options | changes))


def check(c, **changes):
    return c.service.check(
        c.actor, ID, review_id="c" * 32, **(c.options | {"expected_revision": c.records.revision} | changes)
    )


def test_approval_is_separate_bounded_and_never_releases_hold(context):
    c = context
    before = deepcopy(c.records.job)
    receipt = approve(c)
    assert receipt["status"] == "approved" and not receipt["recovery_authorized"]
    assert c.records.job["security_hold"] == before["security_hold"]
    assert c.records.job["promotion_automation_consent"] is None
    review = c.records.job[FIELD]
    assert review["approved_metadata_revision"] == c.records.revision
    assert datetime.fromisoformat(review["expires_at"]) - c.moment[0] == timedelta(seconds=300)
    before, saves = deepcopy(c.records.job), c.records.save_calls
    result = check(c)
    assert result["artifact_review_matched"] and result["read_only"]
    assert not result["execution_authorized"] and not result["credentials_activated"]
    assert c.records.job == before and c.records.save_calls == saves


@pytest.mark.parametrize(
    "change", ["expired", "revision", "metadata", "boundary", "reviewer", "key", "image", "evidence"]
)
def test_changed_or_expired_approval_cannot_pass_recheck(context, change):
    c = context
    approve(c)
    if change == "expired":
        c.moment[0] += timedelta(seconds=301)
    elif change == "revision":
        c.records.revision += 1
    elif change == "metadata":
        c.records.job["result"]["unexpected"] = True
    elif change == "boundary":
        c.records.job["security_review_boundary"]["id"] = "f" * 32
    elif change == "reviewer":
        c.service.reviewer = lambda _: replace(c.actor, role=Role.VIEWER)
    elif change == "image":
        c.inspector.image_registration = replace(
            c.inspector.image_registration,
            image=c.inspector.image_registration.image.split("@")[0] + "@sha256:" + "f" * 64,
        )
    else:
        old = c.inspector.inspect.side_effect

        def altered(*a, **kw):
            proof = old(*a, **kw)
            proof["public_key_fingerprint" if change == "key" else "signature_verified"] = (
                "foreign" if change == "key" else False
            )
            return proof

        c.inspector.inspect.side_effect = altered
    before = c.records.save_calls
    with pytest.raises((ValueError, PermissionError, RecordConflict)):
        check(c)
    assert c.records.save_calls == before


def test_revocation_needs_no_provider_access_and_remains_blocked(context):
    c = context
    approve(c)
    c.service.inspector = None
    result = c.service.revoke(
        c.actor,
        ID,
        review_id="c" * 32,
        review_ref="REVOKE-1",
        **(c.options | {"expected_revision": c.records.revision}),
    )
    assert result["status"] == "revoked" and not result["execution_authorized"]
    with pytest.raises(ValueError):
        check(c)
    c.records.job["security_hold"] = None
    with pytest.raises(ValueError, match="Artifact review"):
        require_no_security_hold(c.records.job)


def test_concurrent_cas_conflict_cannot_overwrite_or_approve(context):
    c = context
    c.records.before_save = lambda records: setattr(records, "revision", records.revision + 1)
    with pytest.raises(RecordConflict):
        approve(c)
    assert FIELD not in c.records.job


def test_uncertain_commit_is_not_retried_or_treated_as_success(context):
    c = context
    c.records.uncertain = True
    before = c.records.save_calls
    with pytest.raises(OSError):
        approve(c)
    assert c.records.save_calls == before + 1
    assert c.records.job[FIELD]["id"] == "c" * 32


def test_expired_review_is_archived_and_identity_cannot_be_reused(context):
    c = context
    approve(c)
    c.moment[0] += timedelta(seconds=301)
    options = c.options | {"expected_revision": c.records.revision}
    with pytest.raises(ValueError):
        c.service.approve(c.actor, ID, review_id="c" * 32, review_ref="REVIEW-2", **options)
    c.service.approve(c.actor, ID, review_id="d" * 32, review_ref="REVIEW-2", **options)
    assert c.records.job[HISTORY][0]["id"] == "c" * 32
    assert c.records.job[FIELD]["id"] == "d" * 32


def test_false_positive_release_cannot_clear_artifact_review(context):
    c = context
    approve(c)
    with pytest.raises(ValueError, match="Artifact review"):
        SecurityHold(c.records).release_false_positive(
            c.actor,
            ID,
            incident_id="INC-1",
            review_ref="FALSE-1",
            expected_revision=c.records.revision,
            expected_boundary=c.options["expected_boundary"],
            now=c.moment[0].isoformat(),
        )


def test_image_registration_change_during_inspection_cannot_be_approved(context):
    c = context
    original = c.inspector.inspect.side_effect

    def changed(*args, **kwargs):
        proof = original(*args, **kwargs)
        c.inspector.image_registration = replace(
            c.inspector.image_registration, source_digest="sha256:" + "f" * 64
        )
        return proof

    c.inspector.inspect.side_effect = changed
    before = c.records.save_calls
    with pytest.raises(RecordConflict, match="registration changed"):
        approve(c)
    assert c.records.save_calls == before and FIELD not in c.records.job
