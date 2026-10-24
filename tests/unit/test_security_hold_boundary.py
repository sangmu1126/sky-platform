"""Post-incident evidence must replace pre-incident approval; no release API."""

from copy import deepcopy

import pytest

from application.database_promotion_workflow import approved_snapshot
from application.operating_review import deployment_observation_binding
from application.security_hold import SecurityHold
from domain.access import Role
from ports.state import RecordConflict
from tests.unit.test_deployment_writes import principal
from tests.unit.test_operating_review import ID, NOW

pytest_plugins = ["tests.unit.test_operating_review"]
LATER = "2026-10-11T00:00:01+00:00"


def test_hold_fences_old_evidence_and_approval_even_after_future_release(operating_review_setup):
    records, policy, review = operating_review_setup
    old = review.review(principal(), ID, policy, now=NOW)
    approved = review.approve(principal(), ID, old["proposal_id"], policy, now=NOW)
    old_health = deepcopy(records.health)
    hold = SecurityHold(records)
    hold.place(principal(role=Role.ADMIN), ID, incident_id="INC-1", reason="untrusted_artifact", now=LATER)
    boundary = deepcopy(records.job["security_review_boundary"])
    assert boundary["recorded_at"] == LATER
    assert records.job["operating_proposal"] == approved  # Preserve the audit record.
    hold.place(principal(role=Role.ADMIN), ID, incident_id="INC-1", reason="untrusted_artifact", now=LATER)
    assert records.job["security_review_boundary"] == boundary
    with pytest.raises(ValueError, match="Security hold"):
        review.review(principal(), ID, policy, now=LATER)
    # Test-only hypothetical release: production intentionally has no such API.
    records.job["security_hold"] = None
    with pytest.raises(ValueError, match="not bound"):
        approved_snapshot(records, principal(), ID, old["proposal_id"], policy, LATER)
    records.health[-1]["deployment_binding"] = deployment_observation_binding(records.job)
    with pytest.raises(ValueError, match="post-incident"):
        review.review(principal(), ID, policy, now=LATER)
    records.health[-1]["checked_at"] = LATER
    records.health_revision += 1
    new = review.review(principal(), ID, policy, now=LATER)
    assert new["proposal_id"] != old["proposal_id"] and new["status"] == "pending_approval"
    with pytest.raises(ValueError):
        approved_snapshot(records, principal(), ID, old["proposal_id"], policy, LATER)
    with pytest.raises(ValueError):
        approved_snapshot(records, principal(), ID, new["proposal_id"], policy, LATER)
    review.approve(principal(), ID, new["proposal_id"], policy, now=LATER)
    assert (
        approved_snapshot(records, principal(), ID, new["proposal_id"], policy, LATER)[1]["status"]
        == "approved"
    )
    assert records.job["operating_proposal_history"][-1] == approved
    assert old_health[0]["deployment_binding"] != records.health[0]["deployment_binding"]
    records.job["security_hold"] = None
    hold.place(principal(role=Role.ADMIN), ID, incident_id="INC-2", reason="credential_exposure", now=LATER)
    assert records.job["security_review_boundary"]["id"] != boundary["id"]


@pytest.mark.parametrize(
    "bad", [None, False, {}, {"id": "x", "recorded_at": NOW}, {"id": "a" * 32, "recorded_at": "invalid"}]
)
def test_corrupt_boundary_blocks_review(operating_review_setup, bad):
    records, policy, review = operating_review_setup
    records.job["security_review_boundary"] = bad
    with pytest.raises(ValueError):
        review.review(principal(), ID, policy, now=NOW)


def test_conflict_does_not_install_a_partial_boundary(operating_review_setup):
    records, _, _ = operating_review_setup
    records.before_save = lambda store: setattr(store, "revision", store.revision + 1)
    with pytest.raises(RecordConflict):
        SecurityHold(records).place(
            principal(role=Role.ADMIN), ID, incident_id="INC-1", reason="untrusted_artifact", now=NOW
        )
    assert "security_review_boundary" not in records.job and "security_hold" not in records.job


def test_projection_boundary_is_detached(operating_review_setup):
    records, _, _ = operating_review_setup
    SecurityHold(records).place(
        principal(role=Role.ADMIN), ID, incident_id="INC-1", reason="untrusted_artifact", now=NOW
    )
    binding = deployment_observation_binding(records.job)
    binding["security_review_boundary"]["id"] = "changed"
    assert records.job["security_review_boundary"]["id"] != "changed"
