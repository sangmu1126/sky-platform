from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from unittest.mock import Mock

import pytest

from application.incident_recovery_inspection import IncidentRecoveryInspection
from domain.access import Role
from ports.state import RecordConflict
from tests.unit.test_incident_artifact_review import context as context  # noqa: PLC0414
from tests.unit.test_incident_recovery import admit
from tests.unit.test_incident_recovery import recovery as recovery  # noqa: PLC0414
from tests.unit.test_operating_review import ID


def inspector(r):
    return IncidentRecoveryInspection(
        r.c.records, clock=lambda: r.c.moment[0].isoformat(), revalidate=lambda: r.c.actor
    )


def inspect(r, service=None):
    options = {k: r.c.options[k] for k in ("incident_id", "expected_boundary")}
    return (service or inspector(r)).inspect(
        r.c.actor, ID, recovery_id="f" * 32, expected_revision=r.c.records.revision, **options
    )


def archive(r):
    admit(r)
    r.service.execute(r.c.actor, ID, recovery_id="f" * 32, **r.c.options)
    record = deepcopy(r.c.records.job["security_recovery"])
    boundary = {"id": "9" * 32, "recorded_at": r.c.moment[0].isoformat()}
    r.c.records.job.update(
        security_recovery=None,
        security_hold=None,
        result=deepcopy(record["result"]),
        security_review_boundary=boundary,
        security_incident_history=[
            {
                "id": "f" * 32,
                "incident_id": record["incident_id"],
                "prior_boundary": record["boundary_id"],
                "new_boundary": boundary,
                "recovered_at": r.c.moment[0].isoformat(),
                "controls": {"security_recovery": record},
            }
        ],
    )


@pytest.mark.parametrize(
    "phase,outcome",
    [
        ("approved", "approval_recorded"),
        ("running", "execution_outcome_unconfirmed"),
        ("verified", "completion_not_recorded"),
        ("needs_attention", "needs_attention"),
    ],
)
def test_pending_phases_are_observed_without_execution_or_repair(recovery, phase, outcome):
    r = recovery
    admit(r)
    if phase != "approved":
        r.c.records.job["security_recovery"].update(phase=phase, external_pending=phase != "verified")
    if phase == "verified":
        r.c.records.job["security_recovery"].update(result=deepcopy(r.result))
    before = deepcopy(r.c.records.job)
    r.runtime.reset_mock()
    r.c.records.save_job = Mock(side_effect=AssertionError("write"))
    report = inspect(r)
    assert report["persisted_outcome"] == outcome and not report["completion_recorded"]
    assert (
        not report["recovery_authorized"]
        and not report["live_runtime_verified"]
        and not report["automatic_retry_allowed"]
    )
    assert r.c.records.job == before and not r.runtime.method_calls and not r.c.records.save_job.called
    assert "plan" not in report and "result" not in report


def test_completed_commit_is_found_after_hold_and_active_record_were_cleared(recovery):
    r = recovery
    archive(r)
    before = deepcopy(r.c.records.job)
    report = inspect(r)
    assert report["completion_recorded"] and report["persisted_outcome"] == "completion_recorded"
    assert report["current_result_matches_record"] and not report["active_hold_recorded"]
    assert report["evidence_source"] == "persisted_metadata" and not report["state_changed"]
    assert r.c.records.job == before
    r.c.records.job["result"] = {"a_later_runtime": "not_this_recovery"}
    assert not inspect(r)["current_result_matches_record"]


def test_expired_approval_still_inspectable_and_does_not_authorize_retry(recovery):
    r = recovery
    admit(r)
    r.c.moment[0] += timedelta(seconds=901)
    assert inspect(r)["approval_expired"] and not inspect(r)["automatic_retry_allowed"]


@pytest.mark.parametrize(
    "change",
    [
        "duplicate",
        "active-and-archive",
        "controls",
        "phase",
        "pending",
        "boundary",
        "lifetime",
        "scope",
        "future",
    ],
)
def test_malformed_or_ambiguous_completion_never_reports_success(recovery, change):
    r = recovery
    archive(r)
    a = r.c.records.job["security_incident_history"][0]
    record = a["controls"]["security_recovery"]
    if change == "duplicate":
        r.c.records.job["security_incident_history"].append(deepcopy(a))
    elif change == "active-and-archive":
        r.c.records.job["security_recovery"] = deepcopy(record)
    elif change == "controls":
        a["controls"] = []
    elif change == "phase":
        record["phase"] = "running"
    elif change == "pending":
        record["external_pending"] = True
    elif change == "boundary":
        a["new_boundary"]["id"] = "bad"
    elif change == "lifetime":
        record["expires_at"] = record["approved_at"]
    elif change == "scope":
        record["incident_id"] = "FOREIGN"
    else:
        a["recovered_at"] = (r.c.moment[0] + timedelta(seconds=1)).isoformat()
        a["new_boundary"]["recorded_at"] = a["recovered_at"]
    with pytest.raises((ValueError, TypeError)):
        inspect(r)


@pytest.mark.parametrize("change", ["revoked", "wrong-org", "changed", "timeout", "missing"])
def test_scope_freshness_and_membership_changes_do_not_disclose_records(recovery, change):
    r = recovery
    admit(r)
    service = inspector(r)
    if change == "revoked":
        service.revalidate = lambda: replace(r.c.actor, role=Role.VIEWER)
    elif change == "wrong-org":
        r.c.records.job["organization_id"] = "foreign"
    elif change == "changed":
        original = service.writer.snapshot
        count = [0]

        def read(*a, **kw):
            count[0] += 1
            if count[0] == 2:
                r.c.records.job["events"] = [{"changed": True}]
            return original(*a, **kw)

        service.writer.snapshot = read
    elif change == "timeout":
        values = iter([r.c.moment[0].isoformat(), (r.c.moment[0] + timedelta(seconds=301)).isoformat()])
        service.clock = lambda: next(values)
    else:
        r.c.records.job["security_recovery"] = None
    with pytest.raises((PermissionError, ValueError, FileNotFoundError, RecordConflict)):
        inspect(r, service)
