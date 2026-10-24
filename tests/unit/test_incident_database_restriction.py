from copy import deepcopy
from dataclasses import replace
from unittest.mock import Mock

import pytest

from application.incident_database_restriction import FIELD, IncidentDatabaseRestriction
from application.security_hold import SecurityHold, require_no_security_hold
from domain.access import Role
from domain.database import DatabaseBinding
from ports.state import RecordConflict
from tests.unit.test_deployment_writes import principal
from tests.unit.test_operating_review import ID, NOW

pytest_plugins = ["tests.unit.test_operating_review"]


def setup(operating_review_setup):
    records, _, _ = operating_review_setup
    actor = principal(role=Role.ADMIN)
    hold = SecurityHold(records)
    hold.place(actor, ID, incident_id="INC-1", reason="credential_exposure", now=NOW)
    binding = DatabaseBinding(**records.job["workload_database_binding"])
    adapter = Mock(binding=binding)

    def execute(*, guard):
        assert records.job[FIELD]["phase"] == "applying"
        guard()
        return {"binding": records.job["workload_database_binding"], "login_enabled": False}

    adapter.restrict.side_effect = execute
    service = IncidentDatabaseRestriction(records, adapter, clock=lambda: NOW, revalidate=lambda: actor)
    args = {
        "incident_id": "INC-1",
        "expected_boundary": records.job["security_review_boundary"]["id"],
        "expected_revision": records.revision,
    }
    return records, actor, adapter, service, args


def test_intent_precedes_effect_and_retries_do_not_run_sql_again(operating_review_setup):
    records, actor, adapter, service, args = setup(operating_review_setup)
    before = deepcopy(records.job["security_hold"])
    result = service.restrict(actor, ID, **args)
    assert result["phase"] == "verified"
    assert service.restrict(actor, ID, **args) == result
    adapter.restrict.assert_called_once()
    assert records.job["security_hold"] == before and records.job["promotion_automation_consent"] is None
    assert service.status(actor, ID)["record_valid"] is True
    records.job["security_hold"] = None  # Unauthorized low-level clear cannot permit promotion.
    with pytest.raises(ValueError, match="Database restriction"):
        require_no_security_hold(records.job)


@pytest.mark.parametrize(
    "change", ["role", "org", "scope", "state-db", "incident", "boundary", "revision", "malformed-boundary"]
)
def test_scope_mismatch_has_no_external_effect(operating_review_setup, change):
    records, actor, adapter, service, args = setup(operating_review_setup)
    if change == "role":
        actor = principal()
    elif change == "org":
        actor = principal(org="other", role=Role.ADMIN)
        service.revalidate = lambda: actor
    elif change == "scope":
        adapter.binding = replace(adapter.binding, database_name="other")
    elif change == "state-db":
        adapter.binding = replace(adapter.binding, role="sky_state")
    elif change == "incident":
        args["incident_id"] = "other"
    elif change == "boundary":
        args["expected_boundary"] = "f" * 32
    elif change == "revision":
        args["expected_revision"] -= 1
    else:
        records.job["security_review_boundary"] = False
    with pytest.raises((PermissionError, ValueError, FileNotFoundError, RecordConflict)):
        service.restrict(actor, ID, **args)
    adapter.restrict.assert_not_called()
    assert FIELD not in records.job


def test_unknown_effect_is_preserved_and_false_positive_cannot_release_it(operating_review_setup):
    records, actor, adapter, service, args = setup(operating_review_setup)
    adapter.restrict.side_effect = OSError("secret connection detail")
    with pytest.raises(OSError) as error:
        service.restrict(actor, ID, **args)
    assert "secret" not in str(error.value)
    assert service.status(actor, ID)["phase"] == "needs_attention"
    assert service.restrict(actor, ID, **args)["phase"] == "needs_attention"
    adapter.restrict.assert_called_once()
    with pytest.raises(ValueError, match="dedicated incident recovery"):
        SecurityHold(records).release_false_positive(
            actor,
            ID,
            incident_id="INC-1",
            review_ref="review",
            expected_revision=records.revision,
            expected_boundary=args["expected_boundary"],
            now=NOW,
        )


def test_uncertain_admission_never_calls_sql(operating_review_setup):
    records, actor, adapter, service, args = setup(operating_review_setup)
    records.uncertain = True
    with pytest.raises(OSError, match="admission uncertain"):
        service.restrict(actor, ID, **args)
    assert service.restrict(actor, ID, **args)["phase"] == "applying"
    adapter.restrict.assert_not_called()


def test_membership_loss_stops_execution_and_leaves_intent_for_inspection(operating_review_setup):
    records, actor, adapter, service, args = setup(operating_review_setup)
    service.revalidate = Mock(side_effect=[actor, principal(), principal()])
    with pytest.raises(OSError):
        service.restrict(actor, ID, **args)
    assert records.job[FIELD]["phase"] == "applying"
    adapter.restrict.assert_not_called()


def test_corrupt_incident_record_is_not_echoed(operating_review_setup):
    records, actor, _, service, _ = setup(operating_review_setup)
    records.job[FIELD] = {"password": "must-not-echo"}
    assert service.status(actor, ID) == {"phase": "needs_attention", "record_valid": False}


def test_restriction_details_are_private_even_if_the_hold_is_missing(operating_review_setup):
    import json

    from tests.unit.test_security_hold_reads import setup as read_setup

    records, actor, _, service, args = setup(operating_review_setup)
    service.restrict(actor, ID, **args)
    job, reads = read_setup(None)
    job.update(deepcopy(records.job))
    job["security_hold"] = None
    detail = reads.detail(principal(role=Role.VIEWER), ID)
    assert FIELD not in detail and "INC-1" not in json.dumps(detail)
    assert detail["security_status"]["promotion_blocked"] is True
    assert detail["security_status"]["status"] == "database_restriction_review_required"


def test_admission_cas_conflict_has_no_sql_effect(operating_review_setup):
    records, actor, adapter, service, args = setup(operating_review_setup)
    records.before_save = lambda store: setattr(store, "revision", store.revision + 1)
    with pytest.raises(RecordConflict):
        service.restrict(actor, ID, **args)
    assert FIELD not in records.job
    adapter.restrict.assert_not_called()


def test_lost_verified_commit_response_never_reexecutes_restriction(operating_review_setup):
    records, actor, adapter, service, args = setup(operating_review_setup)
    save = records.save_job

    def lose_response(job_id, record, *, expected_revision=None):
        revision = save(job_id, record, expected_revision=expected_revision)
        if record.get(FIELD, {}).get("phase") == "verified":
            raise OSError("sensitive commit failure")
        return revision

    records.save_job = lose_response
    with pytest.raises(OSError) as error:
        service.restrict(actor, ID, **args)
    assert "sensitive" not in str(error.value)
    assert service.restrict(actor, ID, **args)["phase"] == "verified"
    adapter.restrict.assert_called_once()


def test_wrong_executor_receipt_never_claims_verified(operating_review_setup):
    records, actor, adapter, service, args = setup(operating_review_setup)
    adapter.restrict.side_effect = None
    adapter.restrict.return_value = {
        "binding": records.job["workload_database_binding"],
        "login_enabled": True,
    }
    with pytest.raises(OSError):
        service.restrict(actor, ID, **args)
    assert records.job[FIELD]["phase"] == "needs_attention"
