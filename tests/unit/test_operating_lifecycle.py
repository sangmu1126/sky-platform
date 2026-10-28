from copy import deepcopy
from unittest.mock import Mock
from uuid import uuid4

import pytest

from application.operating_lifecycle import OperatingLifecycle
from domain.access import Role
from ports.deployment_reads import DeploymentSnapshot, OperatingLifecycleSnapshot
from ports.state import RecordConflict
from tests.unit.test_deployment_writes import ID, Records, principal


def fixture():
    records = Records()
    operation = {
        "id": str(uuid4()),
        "kind": "db_dedicated_prepare",
        "status": "needs_attention",
        "attempt_id": str(uuid4()),
        "row_version": 8,
        "external_pending": True,
        "stage": "target_outcome_uncertain",
        "created_at": "2026-10-28T00:00:00Z",
    }
    reads = Mock(
        lifecycle=lambda *_: OperatingLifecycleSnapshot(
            DeploymentSnapshot(deepcopy(records.job), [], records.revision), (deepcopy(operation),), False
        )
    )
    recovery = Mock(resume=Mock(return_value={"status": "queued"}))
    return OperatingLifecycle(reads, recovery=recovery), records, operation, recovery


def test_read_only_summary_and_admin_recovery_token():
    service, _, op, recovery = fixture()
    read = service.detail(principal(role=Role.VIEWER), ID)
    assert read["phase"] == "needs_attention" and read["observed_only"] and not read["automatic_action"]
    assert "attempt_id" not in read["operations"][0] and not read["operations"][0]["recovery_enabled"]
    assert service.detail(principal(role=Role.ADMIN), ID)["operations"][0]["recovery_enabled"]
    recovery.resume.assert_not_called()
    assert service.resume_preparation(principal(role=Role.ADMIN), ID, op["id"], op["attempt_id"], 8) == {
        "status": "queued"
    }
    recovery.resume.assert_called_once()


@pytest.mark.parametrize(
    "fault", ["foreign", "viewer", "stale", "wrong_operation", "missing_authority", "security"]
)
def test_recovery_cannot_bypass_identity_original_snapshot_or_trusted_authority(fault):
    service, records, op, recovery = fixture()
    actor = principal(role=Role.ADMIN)
    version = 8
    operation_id = op["id"]
    if fault == "foreign":
        actor = principal("other", Role.ADMIN)
    elif fault == "viewer":
        actor = principal(role=Role.VIEWER)
    elif fault == "stale":
        version = 7
    elif fault == "wrong_operation":
        operation_id = str(uuid4())
    elif fault == "missing_authority":
        service.recovery = None
    else:
        records.job["security_secret_access_fence"] = {}
    with pytest.raises((PermissionError, FileNotFoundError, ValueError, RecordConflict)):
        service.resume_preparation(actor, ID, operation_id, op["attempt_id"], version)
    recovery.resume.assert_not_called()


def test_incident_controls_disable_all_operational_capabilities():
    service, records, _, _ = fixture()
    records.job["security_execution_fence"] = {}
    result = service.detail(principal(role=Role.ADMIN), ID)
    assert result["phase"] == "security_hold" and not any(result["capabilities"].values())
    assert not result["operations"][0]["recovery_enabled"]


def test_effect_review_is_write_authorized_even_with_a_trusted_adapter():
    service, _, _, _ = fixture()
    service.reviews = Mock()
    with pytest.raises(PermissionError):
        service.review_effect(principal(role=Role.VIEWER), ID, str(uuid4()))
    service.reviews.review_effect.assert_not_called()
