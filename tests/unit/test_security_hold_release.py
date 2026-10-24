from copy import deepcopy
from unittest.mock import Mock

import pytest

from application.deployment_observation import DeploymentObservationRecorder
from application.security_hold import SecurityHold, require_no_security_hold
from domain.access import Role
from ports.state import RecordConflict
from tests.unit.test_deployment_writes import principal
from tests.unit.test_operating_review import ID, NOW

pytest_plugins = ["tests.unit.test_operating_review"]


def prepared(setup):
    records, policy, review = setup
    proposal = review.review(principal(), ID, policy, now=NOW)
    review.approve(principal(), ID, proposal["proposal_id"], policy, now=NOW)
    actor = principal(role=Role.ADMIN)
    service = SecurityHold(records)
    service.place(actor, ID, incident_id="INC-1", reason="suspected_compromise", now=NOW)
    DeploymentObservationRecorder(
        records,
        Mock(return_value={"healthy": True, "checked_at": NOW, "reason": "HTTP checked"}),
        clock=lambda: NOW,
        revalidate=lambda: actor,
    ).collect(actor, ID)
    args = {
        "incident_id": "INC-1",
        "review_ref": "REVIEW-1",
        "expected_revision": records.revision,
        "expected_boundary": records.job["security_review_boundary"]["id"],
        "now": NOW,
    }
    return records, policy, review, service, actor, args


def test_explicit_false_positive_release_is_audited_and_requires_new_observation_and_approval(
    operating_review_setup,
):
    records, policy, review, service, actor, args = prepared(operating_review_setup)
    previous = deepcopy(records.job["operating_proposal"])
    old_boundary = deepcopy(records.job["security_review_boundary"])
    released = service.release_false_positive(actor, ID, **args)
    assert records.job["security_hold"] is None and records.job["promotion_automation_consent"] is None
    assert released["outcome"] == "false_positive" and released["review_ref"] == "REVIEW-1"
    assert released["hold"]["incident_id"] == "INC-1"
    assert records.job["security_hold_history"] == [released]
    assert records.job["security_review_boundary"]["id"] != old_boundary["id"]
    assert records.job["operating_proposal"] == previous
    require_no_security_hold(records.job)
    with pytest.raises(ValueError, match="not bound"):
        review.review(principal(), ID, policy, now=NOW)
    assert service.status(actor, ID)["status"] == "released_false_positive"
    saved = records.save_calls
    assert service.release_false_positive(actor, ID, **args) == released
    assert records.save_calls == saved
    released["hold"]["incident_id"] = "mutated"
    assert records.job["security_hold_history"][0]["hold"]["incident_id"] == "INC-1"
    DeploymentObservationRecorder(
        records,
        Mock(return_value={"healthy": True, "checked_at": NOW, "reason": "HTTP rechecked"}),
        clock=lambda: NOW,
        revalidate=lambda: actor,
    ).collect(actor, ID)
    fresh = review.review(principal(), ID, policy, now=NOW)
    assert fresh["status"] == "pending_approval" and fresh["proposal_id"] != previous["proposal_id"]
    review.approve(principal(), ID, fresh["proposal_id"], policy, now=NOW)


@pytest.mark.parametrize(
    "change",
    [
        "foreign",
        "deployer",
        "revision",
        "incident",
        "boundary",
        "legacy",
        "bad-hold",
        "bad-history",
        "unhealthy",
        "stale",
        "future",
        "old-binding",
        "unsettled",
    ],
)
def test_invalid_release_never_clears_the_hold(operating_review_setup, change):
    records, _, _, service, actor, args = prepared(operating_review_setup)
    if change == "foreign":
        actor = principal(org="other", role=Role.ADMIN)
    elif change == "deployer":
        actor = principal()
    elif change == "revision":
        args["expected_revision"] -= 1
    elif change == "incident":
        args["incident_id"] = "INC-other"
    elif change == "boundary":
        args["expected_boundary"] = "f" * 32
    elif change == "legacy":
        records.job.pop("security_review_boundary")
    elif change == "bad-hold":
        records.job["security_hold"] = {}
    elif change == "bad-history":
        records.job["security_hold_history"] = {"password": "must-not-echo"}
    elif change == "unhealthy":
        records.health[-1]["healthy"] = False
    elif change == "stale":
        args["now"] = "2026-10-11T00:05:01+00:00"
    elif change == "future":
        records.health[-1]["checked_at"] = "2026-10-12T00:00:00+00:00"
    elif change == "old-binding":
        records.health[-1]["deployment_binding"].pop("security_review_boundary")
    elif change == "unsettled":
        records.job["release_rollback_state"] = "needs_attention"
    before = deepcopy(records.job)
    calls = records.save_calls
    with pytest.raises((ValueError, RecordConflict, PermissionError, FileNotFoundError)):
        service.release_false_positive(actor, ID, **args)
    assert records.job == before and records.save_calls == calls


def test_uncertain_commit_is_reconciled_without_second_release(operating_review_setup):
    records, _, _, service, actor, args = prepared(operating_review_setup)
    records.uncertain = True
    with pytest.raises(OSError):
        service.release_false_positive(actor, ID, **args)
    revision = records.revision
    release = service.release_false_positive(actor, ID, **args)
    assert records.revision == revision and len(records.job["security_hold_history"]) == 1
    assert release["prior_metadata_revision"] == args["expected_revision"]


def test_concurrent_metadata_change_cannot_partially_release(operating_review_setup):
    records, _, _, service, actor, args = prepared(operating_review_setup)
    records.before_save = lambda store: setattr(store, "revision", store.revision + 1)
    before = deepcopy(records.job)
    with pytest.raises(RecordConflict):
        service.release_false_positive(actor, ID, **args)
    assert records.job == before


def test_release_history_is_private_in_deployment_reads(operating_review_setup):
    from tests.unit.test_security_hold_reads import setup

    records, _, _, service, actor, args = prepared(operating_review_setup)
    service.release_false_positive(actor, ID, **args)
    job, reads = setup(None)
    job.update(deepcopy(records.job))
    import json

    for role in (Role.VIEWER, Role.DEPLOYER):
        detail = reads.detail(principal(role=role), ID)
        assert detail["security_status"]["status"] == "released_false_positive"
        assert "security_hold_history" not in detail and "REVIEW-1" not in json.dumps(detail)
        assert "INC-1" not in json.dumps(reads.summaries(principal(role=role)).items)
    assert reads.detail(actor, ID)["security_status"]["release"]["review_ref"] == "REVIEW-1"
