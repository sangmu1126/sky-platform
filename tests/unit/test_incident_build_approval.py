from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from application.incident_build_approval import IncidentBuildApprovalInspection
from ports.state import RecordConflict
from tests.unit.test_kms_build_signature import NOW, signed
from tests.unit.test_kms_build_signature import context as context  # noqa: PLC0414 -- pytest fixture


def setup(c):
    record = {"id": c.request["job_id"], "result": {}}
    approvals = Mock()
    approvals.expected_request.return_value = deepcopy(c.request)
    service = IncidentBuildApprovalInspection(
        Mock(), approvals, c.identity, clock=lambda: NOW.isoformat(), revalidate=Mock()
    )
    service.scope._scope = Mock(return_value=SimpleNamespace(record=record, revision=7))
    args = dict(
        incident_id="INC-1", expected_boundary="b" * 32, expected_revision=7, bundle=signed(c), **c.options
    )
    return service, args, approvals


def invoke(c, service, args):
    with patch(
        "application.incident_build_approval.runtime_identity",
        return_value=(c.identity.account_id, c.identity.region),
    ):
        return service.inspect(Mock(), c.request["job_id"], **args)


def test_signed_claim_matches_independently_read_approval_without_recovery(context):
    c = context
    service, args, approvals = setup(c)
    result = invoke(c, service, args)
    assert approvals.expected_request.call_count == 2
    assert result["signature_verified"] and result["consumed_deployment_approval_matched"]
    assert result["read_only"]
    for key in (
        "current_approval_verified",
        "recovery_authorized",
        "ecr_image_verified",
        "image_safety_verified",
        "key_liveness_checked",
        "state_changed",
    ):
        assert result[key] is False


def test_signed_bundle_cannot_choose_its_own_expected_request(context):
    c = context
    service, args, approvals = setup(c)
    approvals.expected_request.return_value["job_id"] = "f" * 16
    with pytest.raises(OSError, match="hold and access unchanged"):
        invoke(c, service, args)


def test_ledger_change_between_reads_rejects_success(context):
    c = context
    service, args, approvals = setup(c)
    approvals.expected_request.side_effect = [deepcopy(c.request), {**c.request, "job_id": "f" * 16}]
    with pytest.raises(RecordConflict, match="ledger changed"):
        invoke(c, service, args)


@pytest.mark.parametrize("change", ["revision", "incident", "membership"])
def test_changed_review_or_membership_rejects_before_ledger_read(context, change):
    c = context
    service, args, approvals = setup(c)
    if change == "revision":
        args["expected_revision"] = 8
    else:
        service.scope._scope.side_effect = (
            PermissionError("Current administrator required")
            if change == "membership"
            else RecordConflict("Incident changed")
        )
    with pytest.raises((PermissionError, RecordConflict)):
        invoke(c, service, args)
    approvals.expected_request.assert_not_called()


def test_metadata_change_during_ledger_read_rejects_success(context):
    c = context
    service, args, approvals = setup(c)
    original = service.scope._scope.return_value

    def read(*_):
        service.scope._scope.return_value = SimpleNamespace(
            record={"changed": True}, revision=original.revision + 1
        )
        return deepcopy(c.request)

    approvals.expected_request.side_effect = read
    with pytest.raises(RecordConflict):
        invoke(c, service, args)


def test_signature_expiring_during_second_ledger_read_is_not_returned(context):
    c = context
    service, args, _ = setup(c)
    args["bundle"] = signed(c, seconds=10)
    service.clock = Mock(
        side_effect=[NOW.isoformat(), NOW.isoformat(), (NOW + timedelta(seconds=11)).isoformat()]
    )
    with pytest.raises(OSError, match="hold and access unchanged"):
        invoke(c, service, args)
