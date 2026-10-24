from unittest.mock import Mock

import pytest

from application.security_hold import SecurityHold, require_no_security_hold
from domain.access import Role
from tests.unit.test_deployment_writes import Records, principal
from tests.unit.test_operating_review import ID, NOW


def test_admin_records_hold_and_revokes_promotion_automation_in_same_cas():
    records = Records()
    records.job["promotion_automation_consent"] = {"previous": "consent"}
    service = SecurityHold(records)
    hold = service.place(
        principal(role=Role.ADMIN), ID, incident_id="INC-1", reason="suspected_compromise", now=NOW
    )
    assert records.job["security_hold"] == hold
    assert records.job["promotion_automation_consent"] is None
    assert records.save_calls == 1
    hold["reason"] = "changed-copy"
    assert records.job["security_hold"]["reason"] == "suspected_compromise"
    assert (
        service.place(
            principal(role=Role.ADMIN), ID, incident_id="INC-1", reason="suspected_compromise", now=NOW
        )
        == records.job["security_hold"]
    )
    assert records.save_calls == 1


@pytest.mark.parametrize("actor", [None, principal(role=Role.VIEWER), principal(role=Role.DEPLOYER)])
def test_non_admin_cannot_read_or_change_incident_state(actor):
    records = Mock()
    with pytest.raises(PermissionError):
        SecurityHold(records).place(actor, ID, incident_id="INC-1", reason="credential_exposure", now=NOW)
    records.load_job.assert_not_called()
    records.save_job.assert_not_called()


def test_admin_cannot_place_hold_on_foreign_organization():
    records = Records()
    with pytest.raises(FileNotFoundError):
        SecurityHold(records).place(
            principal(org="other", role=Role.ADMIN),
            ID,
            incident_id="INC-1",
            reason="untrusted_artifact",
            now=NOW,
        )
    assert records.save_calls == 0


@pytest.mark.parametrize("hold", [{}, False, "malformed", {"incident_id": "INC-1"}])
def test_any_non_null_hold_blocks_without_implying_clean_legacy_records(hold):
    with pytest.raises(ValueError, match="Security hold"):
        require_no_security_hold({"security_hold": hold})
    require_no_security_hold({})
    require_no_security_hold({"security_hold": None})


def test_existing_incident_is_not_overwritten_by_a_second_incident():
    records = Records()
    service = SecurityHold(records)
    service.place(principal(role=Role.ADMIN), ID, incident_id="INC-1", reason="untrusted_artifact", now=NOW)
    with pytest.raises(ValueError, match="existing security hold"):
        service.place(
            principal(role=Role.ADMIN), ID, incident_id="INC-2", reason="untrusted_artifact", now=NOW
        )
    assert records.job["security_hold"]["incident_id"] == "INC-1"
    assert records.save_calls == 1


def test_concurrent_metadata_write_does_not_silently_lose_the_hold_or_consent():
    from ports.state import RecordConflict

    records = Records()
    records.job["promotion_automation_consent"] = {"existing": True}
    records.before_save = lambda store: setattr(store, "revision", store.revision + 1)
    with pytest.raises(RecordConflict):
        SecurityHold(records).place(
            principal(role=Role.ADMIN), ID, incident_id="INC-1", reason="untrusted_artifact", now=NOW
        )
    assert "security_hold" not in records.job
    assert records.job["promotion_automation_consent"] == {"existing": True}


def test_lost_commit_response_is_reconciled_by_repeating_the_same_incident():
    records = Records()
    records.uncertain = True
    service = SecurityHold(records)
    with pytest.raises(OSError):
        service.place(
            principal(role=Role.ADMIN), ID, incident_id="INC-1", reason="untrusted_artifact", now=NOW
        )
    boundary = records.job["security_review_boundary"].copy()
    result = service.place(
        principal(role=Role.ADMIN), ID, incident_id="INC-1", reason="untrusted_artifact", now=NOW
    )
    assert records.job["security_review_boundary"] == boundary
    assert result == records.job["security_hold"]
    assert records.job["promotion_automation_consent"] is None
    assert records.save_calls == 1
