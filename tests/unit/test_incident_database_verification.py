from copy import deepcopy
from unittest.mock import Mock

import pytest

from application.incident_database_verification import FIELD, IncidentDatabaseVerification
from tests.unit.test_incident_secret_access import fixture
from tests.unit.test_operating_review import ID, NOW

pytest_plugins = ["tests.unit.test_operating_review"]
BASELINE = "sha256:" + "a" * 64


@pytest.fixture
def verification(operating_review_setup):
    f = fixture(operating_review_setup)
    f.service.fence(f.actor, ID, **f.args)
    f.records.job["security_runtime_retirement"] = {"phase": "retired"}
    control = Mock()
    control.inspect.return_value = {
        "sky_worker_external_intents_fenced": True,
        "registered_operation_requests_settled": True,
        "pending_inventory_complete": True,
    }
    retired = Mock()
    retired.inspect.return_value = {
        "registered_runtime_retirement_verified": True,
        "read_only": True,
        "state_changed": False,
    }
    result = {
        "baseline_fingerprint": BASELINE,
        "baseline_matched": True,
        "authentication_verified": True,
        "previous_password_rejected": True,
        "login_enabled": False,
        "active_sessions": 0,
        "credentials_activated": False,
        "recovery_authorized": False,
        "candidate_version_id": f.context["candidate_version_id"],
        "previous_version_id": "c" * 32,
    }
    adapter = Mock()

    def verify(*_, guard, **kw):
        assert f.records.job[FIELD]["phase"] == "applying"
        guard()
        return deepcopy(result)

    adapter.verify.side_effect = verify
    f.verifier = IncidentDatabaseVerification(
        f.records, control, retired, f.registration, adapter, clock=lambda: NOW, revalidate=lambda: f.actor
    )
    f.control, f.retired, f.verify_adapter, f.result = control, retired, adapter, result
    f.args["expected_revision"] = f.records.revision
    return f


def test_authentication_requires_durable_intent_and_stays_restricted(verification):
    f = verification
    report = f.verifier.verify(f.actor, ID, expected_fingerprint=BASELINE, **f.args)
    assert report["phase"] == "verified_restricted"
    assert report["receipt"]["authentication_verified"] and not report["receipt"]["credentials_activated"]
    assert f.records.job["security_hold"] and f.records.job["promotion_automation_consent"] is None
    f.args["expected_revision"] = f.records.revision
    with pytest.raises(ValueError, match="never repeat LOGIN"):
        f.verifier.verify(f.actor, ID, expected_fingerprint=BASELINE, **f.args)
    f.verify_adapter.verify.assert_called_once()


@pytest.mark.parametrize(
    "change",
    [
        "pending",
        "retirement",
        "baseline",
        "foreign-secret",
        "policy",
        "activated",
        "credential-unknown",
        "exception",
    ],
)
def test_incomplete_security_evidence_never_grants_runtime_access(verification, change):
    f = verification
    baseline = BASELINE
    if change == "pending":
        f.control.inspect.return_value["registered_operation_requests_settled"] = False
    if change == "retirement":
        f.retired.inspect.return_value["registered_runtime_retirement_verified"] = False
    if change == "baseline":
        baseline = "invalid"
    if change == "foreign-secret":
        f.records.job["result"]["database"]["secret_arn"] += "foreign"
    if change == "policy":
        f.records.job["security_secret_access_fence"]["phase"] = "applying"
    if change == "activated":
        f.result["credentials_activated"] = True
    if change == "credential-unknown":
        f.result["authentication_verified"] = False
    if change == "exception":
        f.verify_adapter.verify.side_effect = OSError("sensitive native diagnostic")
    with pytest.raises((ValueError, OSError)) as error:
        f.verifier.verify(f.actor, ID, expected_fingerprint=baseline, **f.args)
    assert "sensitive native diagnostic" not in str(error.value)
    assert f.records.job["security_hold"]
    assert f.records.job.get(FIELD, {}).get("phase") != "verified_restricted"
