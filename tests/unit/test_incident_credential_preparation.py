from copy import deepcopy
from dataclasses import asdict, replace
from unittest.mock import Mock

import pytest

from application.incident_credential_preparation import FIELD, IncidentCredentialPreparation
from application.security_hold import SecurityHold, require_no_security_hold, security_hold_projection
from domain.access import Role
from ports.state import RecordConflict
from tests.unit.test_deployment_writes import principal
from tests.unit.test_incident_database_restriction import setup as restriction_setup
from tests.unit.test_operating_review import ID, NOW

pytest_plugins = ["tests.unit.test_operating_review"]


def setup(fixture):
    records, actor, restriction, service, args = restriction_setup(fixture)
    restricted = service.restrict(actor, ID, **args)
    preparation = Mock(
        binding=restriction.binding,
        resource_id="db-PINNED",
        principal_arn=f"arn:aws:iam::{restriction.binding.account_id}:user/preparer",
    )

    def prepare(operation_id, *, guard):
        guard()
        assert records.job[FIELD]["phase"] == "applying"
        binding = restriction.binding
        return {
            "binding": asdict(binding),
            "resource_id": preparation.resource_id,
            "candidate_secret_ref": f"arn:aws:secretsmanager:{binding.region}:{binding.account_id}:secret:sky-incident/{preparation.resource_id}/{operation_id}-test01",
            "candidate_version_id": operation_id,
            "password_update_acknowledged": True,
            "login_enabled": False,
            "active_sessions": 0,
            "authentication_verified": False,
            "runtime_access_granted": False,
            "candidate_access_principal": preparation.principal_arn,
        }

    preparation.prepare.side_effect = prepare
    service = IncidentCredentialPreparation(
        records, restriction, preparation, clock=lambda: NOW, revalidate=lambda: actor
    )
    args = {
        **args,
        "expected_operation_id": restricted["operation_id"],
        "expected_revision": records.revision,
    }
    return records, actor, restriction, preparation, service, args


def test_durable_intent_precedes_secret_sql_and_does_not_release_or_grant_runtime_access(
    operating_review_setup,
):
    records, actor, _, preparation, service, args = setup(operating_review_setup)
    hold = deepcopy(records.job["security_hold"])
    binding = deepcopy(records.job["workload_database_binding"])
    result = service.prepare(actor, ID, **args)
    assert result["phase"] == "prepared_restricted" and result["authentication_verified"] is False
    assert records.job["security_hold"] == hold and records.job["workload_database_binding"] == binding
    assert records.job["promotion_automation_consent"] is None
    assert service.prepare(actor, ID, **args) == result
    preparation.prepare.assert_called_once()
    assert service.status(actor, ID)["record_valid"] is True
    records.job["security_database_restriction"] = None
    records.job["security_hold"] = None
    with pytest.raises(ValueError):
        require_no_security_hold(records.job)
    assert security_hold_projection(records.job)["promotion_blocked"] is True
    with pytest.raises(ValueError):
        SecurityHold(records).release_false_positive(
            actor,
            ID,
            incident_id=args["incident_id"],
            review_ref="review",
            expected_revision=records.revision,
            expected_boundary=args["expected_boundary"],
            now=NOW,
        )


@pytest.mark.parametrize(
    "change", ["revision", "operation", "boundary", "incident", "role", "binding", "uncertain-restriction"]
)
def test_invalid_admission_has_no_external_effect(operating_review_setup, change):
    records, actor, _, preparation, service, args = setup(operating_review_setup)
    if change == "revision":
        args["expected_revision"] -= 1
    elif change == "operation":
        args["expected_operation_id"] = "f" * 32
    elif change == "boundary":
        args["expected_boundary"] = "f" * 32
    elif change == "incident":
        args["incident_id"] = "other"
    elif change == "role":
        actor = principal(role=Role.VIEWER)
    elif change == "binding":
        preparation.binding = replace(preparation.binding, application_id="other")
    else:
        records.job["security_database_restriction"]["phase"] = "applying"
    with pytest.raises((ValueError, PermissionError, RecordConflict)):
        service.prepare(actor, ID, **args)
    preparation.prepare.assert_not_called()
    assert FIELD not in records.job


def test_uncertain_admission_or_external_effect_is_not_replayed(operating_review_setup):
    records, actor, _, preparation, service, args = setup(operating_review_setup)
    records.uncertain = True
    with pytest.raises(OSError):
        service.prepare(actor, ID, **args)
    assert service.prepare(actor, ID, **args)["phase"] == "applying"
    preparation.prepare.assert_not_called()


def test_unknown_secret_or_password_outcome_retains_safe_metadata_only(operating_review_setup):
    records, actor, _, preparation, service, args = setup(operating_review_setup)
    preparation.prepare.side_effect = OSError("must-not-disclose-password")
    with pytest.raises(OSError) as error:
        service.prepare(actor, ID, **args)
    assert "must-not" not in str(error.value)
    assert records.job[FIELD]["phase"] == "needs_attention"
    assert service.prepare(actor, ID, **args)["phase"] == "needs_attention"
    preparation.prepare.assert_called_once()


def test_receipt_cannot_claim_enabled_login_or_hide_extra_secret_fields(operating_review_setup):
    records, actor, _, preparation, service, args = setup(operating_review_setup)
    effect = preparation.prepare.side_effect
    preparation.prepare.side_effect = lambda *a, **kw: {**effect(*a, **kw), "password": "must-not-save"}
    with pytest.raises(OSError):
        service.prepare(actor, ID, **args)
    assert "password" not in str(records.job[FIELD])
    records.job[FIELD] = {"password": "must-not-echo"}
    assert service.status(actor, ID) == {"phase": "needs_attention", "record_valid": False}


def test_changed_incident_or_revoked_membership_blocks_sql_stage(operating_review_setup):
    records, actor, _, preparation, service, args = setup(operating_review_setup)

    def effect(operation_id, *, guard):
        records.job["security_review_boundary"]["id"] = "f" * 32
        guard()
        raise AssertionError("Effect should have been denied")

    preparation.prepare.side_effect = effect
    with pytest.raises(OSError):
        service.prepare(actor, ID, **args)
    assert records.job[FIELD]["phase"] == "applying"


@pytest.mark.parametrize(
    "field,value",
    [
        ("login_enabled", True),
        ("authentication_verified", True),
        ("runtime_access_granted", True),
        ("candidate_version_id", "b" * 32),
        ("resource_id", "db-FOREIGN"),
        ("candidate_access_principal", "arn:aws:iam::111111111111:user/other"),
    ],
)
def test_misleading_preparation_receipt_never_marks_completion(operating_review_setup, field, value):
    records, actor, _, preparation, service, args = setup(operating_review_setup)
    original = preparation.prepare.side_effect
    preparation.prepare.side_effect = lambda *a, **kw: {**original(*a, **kw), field: value}
    with pytest.raises(OSError):
        service.prepare(actor, ID, **args)
    assert records.job[FIELD]["phase"] == "needs_attention"
    assert records.job["security_hold"] is not None
