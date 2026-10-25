from copy import deepcopy

import pytest

from application.incident_credential_preparation import FIELD
from domain.access import Role
from ports.state import RecordConflict
from tests.unit.test_deployment_writes import principal
from tests.unit.test_incident_credential_preparation import setup as preparation_setup
from tests.unit.test_operating_review import ID

pytest_plugins = ["tests.unit.test_operating_review"]


def setup(fixture, phase="applying"):
    records, actor, _restriction, preparation, service, args = preparation_setup(fixture)
    prepared = service.prepare(actor, ID, **args)
    record = deepcopy(prepared)
    if phase != "prepared_restricted":
        for name in (
            "candidate_secret_ref",
            "candidate_version_id",
            "prepared_at",
            "password_update_acknowledged",
            "login_enabled",
            "active_sessions",
            "authentication_verified",
            "runtime_access_granted",
        ):
            record.pop(name)
        record["phase"] = phase
        if phase == "needs_attention":
            record["failure_code"] = "outcome_unconfirmed"
    records.job[FIELD] = record
    receipt = {
        "binding": record["binding"],
        "resource_id": record["resource_id"],
        "candidate_access_principal": record["candidate_access_principal"],
        "candidate_state": "registered_candidate",
        "candidate_secret_ref": prepared["candidate_secret_ref"],
        "candidate_version_id": prepared["operation_id"],
        "login_enabled": False,
        "active_sessions": 0,
        "read_only": True,
        "password_update_verified": False,
        "authentication_verified": False,
    }
    preparation.inspect.side_effect = lambda operation_id, guard: (guard(), deepcopy(receipt))[1]
    preparation.prepare.reset_mock()
    preparation.prepare.side_effect = AssertionError("Inspection must not prepare credentials")
    args.update(expected_operation_id=prepared["operation_id"], expected_revision=records.revision)
    return records, actor, preparation, service, args, receipt


@pytest.mark.parametrize("phase", ["applying", "needs_attention", "prepared_restricted"])
def test_inspection_never_promotes_persisted_phase_or_claims_password_authentication(
    operating_review_setup, phase
):
    records, actor, preparation, service, args, _ = setup(operating_review_setup, phase)
    before, writes = deepcopy(records.job), records.save_calls
    result = service.inspect(actor, ID, **args)
    assert result["persisted_phase"] == phase and result["observed_state"] == "restricted_candidate_observed"
    assert result["state_changed"] is False and result["execution_exclusion_verified"] is False
    assert result["password_update_verified"] is False and result["authentication_verified"] is False
    assert records.job == before and records.save_calls == writes
    preparation.prepare.assert_not_called()


@pytest.mark.parametrize(
    "candidate,state",
    [
        ("not_found", "candidate_not_found"),
        ("policy_unverified", "candidate_review_required"),
        ("version_mismatch", "candidate_review_required"),
        ("scheduled_for_deletion", "candidate_review_required"),
    ],
)
def test_partial_candidate_states_remain_unresolved(operating_review_setup, candidate, state):
    records, actor, _, service, args, receipt = setup(operating_review_setup)
    receipt.update(candidate_state=candidate, candidate_version_id=None)
    if candidate == "not_found":
        receipt["candidate_secret_ref"] = None
    result = service.inspect(actor, ID, **args)
    assert result["observed_state"] == state and records.job[FIELD]["phase"] == "applying"


@pytest.mark.parametrize("login,sessions", [(True, 0), (False, 1)])
def test_unrestricted_database_is_not_hidden_by_valid_secret(operating_review_setup, login, sessions):
    records, actor, _, service, args, receipt = setup(operating_review_setup)
    receipt.update(login_enabled=login, active_sessions=sessions)
    assert service.inspect(actor, ID, **args)["observed_state"] == "database_not_restricted"
    assert records.job["security_hold"] is not None


@pytest.mark.parametrize("change", ["revision", "operation", "boundary", "principal", "role", "binding"])
def test_wrong_snapshot_has_no_probe_or_write(operating_review_setup, change):
    records, actor, preparation, service, args, _ = setup(operating_review_setup)
    if change == "revision":
        args["expected_revision"] -= 1
    elif change == "operation":
        args["expected_operation_id"] = "f" * 32
    elif change == "boundary":
        args["expected_boundary"] = "f" * 32
    elif change == "principal":
        preparation.principal_arn = "arn:aws:iam::111111111111:user/foreign"
    elif change == "binding":
        records.job[FIELD]["binding"]["application_id"] = "foreign"
    else:
        actor = principal(role=Role.VIEWER)
    writes = records.save_calls
    with pytest.raises((ValueError, RecordConflict, PermissionError)):
        service.inspect(actor, ID, **args)
    preparation.inspect.assert_not_called()
    assert records.save_calls == writes


@pytest.mark.parametrize("change", ["revision", "membership", "error", "password", "claim"])
def test_probe_races_and_untrusted_receipts_are_sanitized(operating_review_setup, change):
    records, actor, preparation, service, args, receipt = setup(operating_review_setup)

    def probe(operation_id, *, guard):
        guard()
        if change == "revision":
            records.revision += 1
        elif change == "membership":
            service.scope.revalidate = lambda: principal(role=Role.VIEWER)
        elif change == "error":
            raise OSError("must-not-disclose")
        elif change == "password":
            receipt["password"] = "must-not-disclose"
        else:
            receipt["password_update_verified"] = True
        return receipt

    preparation.inspect.side_effect = probe
    writes = records.save_calls
    with pytest.raises((OSError, RecordConflict, PermissionError)) as error:
        service.inspect(actor, ID, **args)
    assert "must-not-disclose" not in str(error.value) and records.save_calls == writes
