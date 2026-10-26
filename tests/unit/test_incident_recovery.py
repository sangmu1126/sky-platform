from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from application.incident_recovery import FIELD, IncidentRecovery
from ports.state import RecordConflict
from tests.unit.test_incident_artifact_review import approve
from tests.unit.test_incident_artifact_review import context as context  # noqa: PLC0414
from tests.unit.test_operating_review import ID


@pytest.fixture
def recovery(context):
    c = context
    c.records.job["security_hold"]["reason"] = "credential_exposure"
    c.records.job["security_database_verification"] = {
        "phase": "verified_restricted",
        "candidate_version_id": "d" * 32,
        "baseline_fingerprint": "sha256:" + "e" * 64,
        "receipt": {
            "authentication_verified": True,
            "previous_password_rejected": True,
            "baseline_matched": True,
            "credentials_activated": False,
            "login_enabled": False,
        },
    }
    approve(c)
    c.options["expected_revision"] = c.records.revision
    prereq = Mock()
    runtime = Mock()
    plan = {"image": c.inspector.image_registration.image, "candidate_version_id": "d" * 32, "id": "f" * 32}
    runtime.preflight.side_effect = lambda *_, guard, **kw: (guard(), deepcopy(plan))[1]
    for name in ["activate", "deploy"]:
        getattr(runtime, name).side_effect = lambda *_, guard, **kw: (guard(), {})[1]
    result = {
        "image": plan["image"],
        "verification": {"http": "verified", "database_authentication": "verified"},
    }
    runtime.verify.side_effect = lambda *_, guard, **kw: (guard(), deepcopy(result))[1]
    runtime.restrict.return_value = {"login_enabled": False, "provider_outcome_settled": False}
    completion = Mock()
    completion.complete_recovery.return_value = {"phase": "recovered"}
    service = IncidentRecovery(
        c.records,
        prereq,
        c.service,
        runtime,
        completion,
        clock=lambda: c.moment[0].isoformat(),
        revalidate=lambda: c.actor,
        reviewer=lambda user: c.actor,
    )
    return SimpleNamespace(
        c=c, service=service, runtime=runtime, completion=completion, result=result, plan=plan
    )


def admit(r):
    report = r.service.approve(
        r.c.actor, ID, recovery_id="f" * 32, review_id="c" * 32, approval_ref="RECOVERY-1", **r.c.options
    )
    r.c.options["expected_revision"] = r.c.records.revision
    return report


def execute(r):
    return r.service.execute(r.c.actor, ID, recovery_id="f" * 32, **r.c.options)


def test_distinct_approval_does_not_execute_then_only_one_attempt_runs(recovery):
    r = recovery
    approved = admit(r)
    assert not approved["execution_started"] and not approved["hold_released"]
    r.runtime.activate.assert_not_called()
    assert execute(r)["phase"] == "recovered"
    assert r.c.records.job[FIELD]["phase"] == "verified"
    r.runtime.activate.assert_called_once()
    r.completion.complete_recovery.assert_called_once()
    r.c.options["expected_revision"] = r.c.records.revision
    with pytest.raises(ValueError, match="unused current"):
        execute(r)
    r.runtime.activate.assert_called_once()


@pytest.mark.parametrize("change", ["expired", "revoked-review", "plan", "metadata", "image"])
def test_stale_or_changed_approval_never_activates(recovery, change):
    r = recovery
    admit(r)
    if change == "expired":
        r.c.moment[0] += timedelta(seconds=901)
    if change == "revoked-review":
        r.c.records.job["security_artifact_review"]["revoked_at"] = r.c.moment[0].isoformat()
    if change == "plan":
        r.c.records.job[FIELD]["plan"]["image"] += "foreign"
    if change == "metadata":
        r.c.records.job["events"] = [{"changed": True}]
    if change == "image":
        r.plan["image"] += "foreign"
    with pytest.raises((ValueError, RecordConflict)):
        execute(r)
    r.runtime.activate.assert_not_called()
    r.runtime.restrict.assert_not_called()


@pytest.mark.parametrize("stage", ["activate", "deploy", "verify", "bad-http"])
def test_uncertain_activation_or_unverified_candidate_is_restricted_not_replayed(recovery, stage):
    r = recovery
    admit(r)
    if stage == "bad-http":
        r.result["verification"]["http"] = "unknown"
    else:
        getattr(r.runtime, stage).side_effect = OSError("sensitive native failure")
    with pytest.raises(OSError) as error:
        execute(r)
    assert "sensitive native failure" not in str(error.value)
    assert r.c.records.job[FIELD]["phase"] == "needs_attention"
    r.runtime.restrict.assert_called_once()
    r.completion.complete_recovery.assert_not_called()
    r.c.options["expected_revision"] = r.c.records.revision
    with pytest.raises(ValueError):
        execute(r)
    assert r.c.records.job["security_hold"]


def test_uncertain_final_commit_does_not_stop_a_possibly_committed_runtime(recovery):
    r = recovery
    admit(r)
    r.completion.complete_recovery.side_effect = OSError("lost commit acknowledgement")
    with pytest.raises(OSError, match="commit outcome requires inspection"):
        execute(r)
    r.runtime.restrict.assert_not_called()
    assert r.c.records.job[FIELD]["phase"] == "verified"


def test_untrusted_artifact_cannot_reuse_credential_only_recovery(recovery):
    r = recovery
    r.c.records.job["security_hold"]["reason"] = "untrusted_artifact"
    with pytest.raises(ValueError, match="only restores reviewed unchanged"):
        admit(r)
    r.runtime.preflight.assert_not_called()


def test_key_or_image_recheck_failure_after_runtime_verification_keeps_hold(recovery):
    r = recovery
    admit(r)
    inspect = r.c.inspector.inspect.side_effect

    def changed(*args, **kwargs):
        if r.runtime.verify.called:
            raise OSError("key disabled or image removed")
        return inspect(*args, **kwargs)

    r.c.inspector.inspect.side_effect = changed
    with pytest.raises(OSError, match="outcome requires inspection"):
        execute(r)
    r.runtime.restrict.assert_called_once()
    r.completion.complete_recovery.assert_not_called()
    assert r.c.records.job["security_hold"] and r.c.records.job[FIELD]["phase"] == "needs_attention"
