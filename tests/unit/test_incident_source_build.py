from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from application.incident_source_build import IncidentSourceBuildApproval
from domain.access import Role
from ports.remote_builds import BuildSettings
from ports.source_build_approvals import validate_source_build_approval
from ports.state import RecordConflict
from tests.unit.test_deployment_writes import ID
from tests.unit.test_incident_source_review import approve
from tests.unit.test_incident_source_review import review as review  # noqa: PLC0414

APPROVAL = "e" * 32
BUILD = "00000000-0000-4000-8000-000000000001"


class Ledger:
    def __init__(self):
        self.values = {}
        self.uncertain = False

    def create(self, actor, approval, snapshot):
        if self.values:
            raise RecordConflict("Already approved")
        self.values[approval["id"]] = deepcopy(approval)
        if self.uncertain:
            raise OSError("Commit acknowledgement lost")

    def load(self, actor, approval_id):
        return deepcopy(self.values[approval_id])

    def revoke(self, actor, approval, snapshot, *, now, review_ref):
        if approval["revoked_at"] is not None:
            raise ValueError("Already revoked")
        value = validate_source_build_approval(
            {**approval, "revoked_at": now, "revoked_by": actor.user_id, "revocation_ref": review_ref}
        )
        self.values[approval["id"]] = deepcopy(value)
        return deepcopy(value)


@pytest.fixture
def context(review):
    r = review
    approve(r)
    ledger = Ledger()
    settings = BuildSettings(
        "owner/builder", "main", "1" * 40, "2" * 40, "source-bucket", "111111111111", "ap-northeast-2"
    )
    service = IncidentSourceBuildApproval(
        r.service, ledger, settings, clock=lambda: r.moment[0].isoformat(), reviewer=lambda _: r.actor
    )
    return SimpleNamespace(r=r, ledger=ledger, service=service, settings=settings)


def consent(c, **kwargs):
    return c.service.approve(
        c.r.actor,
        ID,
        review_id="c" * 32,
        approval_id=APPROVAL,
        build_id=BUILD,
        review_ref="BUILD-REVIEW-1",
        seconds=300,
        **{**c.r.options, **kwargs},
    )


def test_consent_preserves_held_job_revision_and_does_not_execute(context):
    c = context
    before = deepcopy(c.r.records.job)
    saves = c.r.records.save_calls
    report = consent(c)
    assert report["build_consent_recorded"] and report["state_changed"]
    assert c.r.records.job == before and c.r.records.save_calls == saves
    assert c.ledger.values[APPROVAL]["expires_at"] == before["security_recovery_source_review"]["expires_at"]
    checked = c.service.check(c.r.actor, ID, approval_id=APPROVAL, **c.r.options)
    assert checked["read_only"]
    for field in [
        "execution_authorized",
        "dispatch_requested",
        "recovery_authorized",
        "hold_released",
        "image_safety_verified",
    ]:
        assert report[field] is checked[field] is False
    assert c.r.service.check(c.r.actor, ID, review_id="c" * 32, candidate=c.r.artifact, **c.r.options)[
        "source_snapshot_verified"
    ]


@pytest.mark.parametrize(
    "change",
    [
        "source-expired",
        "source-revoked",
        "source-tampered",
        "metadata",
        "role",
        "bad-approval",
        "bad-build",
        "ttl-bool",
    ],
)
def test_invalid_consent_never_writes_ledger(context, change):
    c = context
    if change == "source-expired":
        c.r.moment[0] += timedelta(seconds=300)
    elif change == "source-revoked":
        c.r.records.job["security_recovery_source_review"]["revoked_at"] = c.r.moment[0].isoformat()
    elif change == "source-tampered":
        c.r.store.objects[c.r.artifact.key] = b"tampered"
    elif change == "metadata":
        c.r.records.revision += 1
    elif change == "role":
        c.r.service.scope.revalidate = lambda: replace(c.r.actor, role=Role.VIEWER)
    args = {
        "review_id": "c" * 32,
        "approval_id": APPROVAL,
        "build_id": BUILD,
        "review_ref": "BUILD-REVIEW-1",
        "seconds": 300,
    }
    if change == "bad-approval":
        args["approval_id"] = "bad"
    if change == "bad-build":
        args["build_id"] = "not-a-uuid"
    if change == "ttl-bool":
        args["seconds"] = True
    with pytest.raises((ValueError, PermissionError, RecordConflict)):
        c.service.approve(c.r.actor, ID, **args, **c.r.options)
    assert not c.ledger.values


@pytest.mark.parametrize(
    "change",
    [
        "expired",
        "revoked",
        "builder",
        "approver",
        "metadata",
        "tampered-source",
        "ledger-change",
        "slow-ledger",
    ],
)
def test_check_refuses_changed_binding_without_writes(context, change):
    c = context
    consent(c)
    if change == "expired":
        c.r.moment[0] += timedelta(seconds=300)
    elif change == "revoked":
        c.service.revoke(c.r.actor, ID, approval_id=APPROVAL, review_ref="REVOKE-1", **c.r.options)
    elif change == "builder":
        c.service.settings = replace(c.settings, workflow_sha="3" * 40)
    elif change == "approver":
        c.service.reviewer = lambda _: replace(c.r.actor, role=Role.VIEWER)
    elif change == "metadata":
        c.r.records.job["unexpected_change"] = True
    elif change == "tampered-source":
        c.r.store.objects[c.r.artifact.key] = b"tampered"
    elif change == "ledger-change":
        original = c.ledger.load

        def changed(*args):
            result = original(*args)
            c.ledger.values[APPROVAL]["review_ref"] = "CHANGED"
            return result

        c.ledger.load = changed
    else:
        original = c.ledger.load

        def slow(*args):
            result = original(*args)
            c.r.moment[0] += timedelta(seconds=301)
            return result

        c.ledger.load = slow
    before = deepcopy(c.r.records.job)
    with pytest.raises((ValueError, PermissionError, RecordConflict)):
        c.service.check(c.r.actor, ID, approval_id=APPROVAL, **c.r.options)
    assert c.r.records.job == before


def test_offline_inspection_and_revocation_after_source_supersession(context):
    c = context
    consent(c)
    c.r.moment[0] += timedelta(seconds=300)
    report = c.r.service.supersede(
        c.r.actor,
        ID,
        predecessor_review_id="c" * 32,
        candidate=c.r.artifact,
        review_id="f" * 32,
        review_ref="NEXT",
        seconds=300,
        **c.r.options,
    )
    c.r.options["expected_revision"] = report["metadata_revision"]
    c.r.service.sources = None
    c.service.settings = None
    c.service.reviewer = Mock(side_effect=AssertionError("Old reviewer lookup"))
    read = c.service.inspect(c.r.actor, ID, approval_id=APPROVAL, **c.r.options)
    assert read["status"] == "expired" and not read["source_binding_current"]
    revoked = c.service.revoke(c.r.actor, ID, approval_id=APPROVAL, review_ref="REVOKE-1", **c.r.options)
    assert revoked["status"] == "revoked"


def test_uncertain_commit_is_inspected_without_automatic_replay(context):
    c = context
    c.ledger.uncertain = True
    with pytest.raises(OSError):
        consent(c)
    assert c.service.inspect(c.r.actor, ID, approval_id=APPROVAL, **c.r.options)["status"] == "approved"
    with pytest.raises(RecordConflict):
        consent(c)
    assert len(c.ledger.values) == 1


@pytest.mark.parametrize(
    "change",
    [
        "extra-key",
        "prepared-source",
        "foreign-app",
        "untrusted-builder-field",
        "unpinned-workflow",
        "no-timezone",
        "overlong-lifetime",
        "boolean-revision",
        "wrong-scope",
    ],
)
def test_build_contract_rejects_unsafe_or_ambiguous_documents(context, change):
    c = context
    consent(c)
    value = deepcopy(c.ledger.values[APPROVAL])
    if change == "extra-key":
        value["command"] = "execute-user-code"
    elif change == "prepared-source":
        value["candidate"]["kind"] = "prepared"
    elif change == "foreign-app":
        value["candidate"]["application_id"] = "foreign"
    elif change == "untrusted-builder-field":
        value["builder"]["credentials"] = "not-allowed"
    elif change == "unpinned-workflow":
        value["builder"]["workflow_sha"] = "main"
    elif change == "no-timezone":
        value["approved_at"] = "2026-10-27T00:00:00"
    elif change == "overlong-lifetime":
        value["expires_at"] = (c.r.moment[0] + timedelta(seconds=901)).isoformat()
    elif change == "boolean-revision":
        value["metadata_revision"] = True
    else:
        value["scope"] = "execute-and-recover"
    with pytest.raises((ValueError, TypeError)):
        validate_source_build_approval(value)
