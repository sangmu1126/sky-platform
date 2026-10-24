from copy import deepcopy

import pytest

from application.incident_database_restriction import FIELD
from domain.access import Role
from ports.state import RecordConflict
from tests.unit.test_deployment_writes import principal
from tests.unit.test_incident_database_restriction import setup
from tests.unit.test_operating_review import ID

pytest_plugins = ["tests.unit.test_operating_review"]


def inspection_setup(operating_review_setup):
    records, actor, adapter, service, args = setup(operating_review_setup)
    result = service.restrict(actor, ID, **args)
    inspect_args = {
        **args,
        "expected_revision": records.revision,
        "expected_operation_id": result["operation_id"],
    }
    adapter.inspect.return_value = {
        "binding": records.job["workload_database_binding"],
        "login_enabled": False,
        "active_sessions": 0,
        "read_only": True,
    }
    return records, actor, adapter, service, inspect_args


@pytest.mark.parametrize(
    "login,sessions,state", [(False, 0, "restricted"), (False, 2, "incomplete"), (True, 1, "not_restricted")]
)
def test_live_state_is_not_assumed_from_persisted_verified_status(
    operating_review_setup, login, sessions, state
):
    records, actor, adapter, service, args = inspection_setup(operating_review_setup)
    adapter.inspect.return_value.update(login_enabled=login, active_sessions=sessions)
    before = deepcopy(records.job)
    writes = records.save_calls
    result = service.inspect(actor, ID, **args)
    assert result["persisted_phase"] == "verified" and result["observed_state"] == state
    assert result["execution_exclusion_verified"] is False and result["state_changed"] is False
    assert records.job == before and records.save_calls == writes
    adapter.restrict.assert_called_once()


def test_unknown_admission_can_be_inspected_without_replaying_or_completing_it(operating_review_setup):
    records, actor, adapter, service, args = setup(operating_review_setup)
    records.uncertain = True
    with pytest.raises(OSError):
        service.restrict(actor, ID, **args)
    operation = records.job[FIELD]
    adapter.inspect.return_value = {
        "binding": operation["binding"],
        "login_enabled": False,
        "active_sessions": 0,
        "read_only": True,
    }
    result = service.inspect(
        actor,
        ID,
        **{**args, "expected_revision": records.revision, "expected_operation_id": operation["operation_id"]},
    )
    assert result["persisted_phase"] == "applying" and result["observed_state"] == "restricted"
    assert records.job[FIELD]["phase"] == "applying"
    adapter.restrict.assert_not_called()


@pytest.mark.parametrize(
    "change",
    [
        {"read_only": False},
        {"active_sessions": True},
        {"active_sessions": -1},
        {"login_enabled": "false"},
        {"binding": {}},
    ],
)
def test_incomplete_or_non_readonly_observations_are_not_accepted(operating_review_setup, change):
    records, actor, adapter, service, args = inspection_setup(operating_review_setup)
    adapter.inspect.return_value.update(change)
    writes = records.save_calls
    with pytest.raises(OSError):
        service.inspect(actor, ID, **args)
    assert records.save_calls == writes


def test_operation_mismatch_and_membership_change_prevent_inspection(operating_review_setup):
    records, actor, adapter, service, args = inspection_setup(operating_review_setup)
    with pytest.raises(ValueError):
        service.inspect(actor, ID, **{**args, "expected_operation_id": "f" * 32})
    adapter.inspect.assert_not_called()
    lost = [False]
    service.revalidate = lambda: principal(role=Role.VIEWER) if lost[0] else actor
    receipt = adapter.inspect.return_value.copy()

    def observe(*, guard):
        lost[0] = True
        return receipt

    adapter.inspect.side_effect = observe
    writes = records.save_calls
    with pytest.raises(PermissionError):
        service.inspect(actor, ID, **args)
    assert records.save_calls == writes


def test_revision_change_during_probe_and_sql_errors_are_safe(operating_review_setup):
    records, actor, adapter, service, args = inspection_setup(operating_review_setup)
    receipt = adapter.inspect.return_value.copy()

    def observe(*, guard):
        records.revision += 1
        return receipt

    adapter.inspect.side_effect = observe
    with pytest.raises(RecordConflict):
        service.inspect(actor, ID, **args)
    adapter.inspect.side_effect = OSError("sensitive postgres DSN")
    with pytest.raises(OSError) as error:
        service.inspect(actor, ID, **{**args, "expected_revision": records.revision})
    assert "sensitive" not in str(error.value)
