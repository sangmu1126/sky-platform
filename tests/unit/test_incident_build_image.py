from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from domain.recovery_image import RecoveryImageRegistration
from ports.state import RecordConflict
from tests.unit.test_incident_build_approval import setup
from tests.unit.test_kms_build_key import native
from tests.unit.test_kms_build_signature import NOW
from tests.unit.test_kms_build_signature import context as context  # noqa: PLC0414


def combined(c):
    service, args, approvals = setup(c)
    service.scope._scope.return_value.record["application_id"] = "signing"
    service.key_observer, _, _, _ = native(c.identity)
    service.image_registration = RecoveryImageRegistration(
        organization_id="fixture",
        application_id="signing",
        job_id=c.request["job_id"],
        incident_id=args["incident_id"],
        boundary_id=args["expected_boundary"],
        account_id=c.identity.account_id,
        region=c.identity.region,
        image=f"{c.identity.account_id}.dkr.ecr.{c.identity.region}.amazonaws.com/recovery@{c.options['image_digest']}",
        config_digest=c.options["config_digest"],
        source_revision=c.request["workflow_sha"],
        source_digest="sha256:" + c.request["source_digest"],
        build_reference=f"https://github.com/{c.request['repository']}/actions/runs/123",
    )
    service.image_inspector = Mock(
        inspect=Mock(
            return_value={
                "image": service.image_registration.image,
                "config_digest": c.options["config_digest"],
                "manifest_bytes_verified": True,
                "config_descriptor_verified": True,
                "source_provenance_verified": False,
                "image_safety_verified": False,
                "recovery_authorized": False,
                "state_changed": False,
                "read_only": True,
                "observed_at": NOW.isoformat(),
            }
        )
    )
    return service, args, approvals


def invoke(c, service, args):
    with patch(
        "application.incident_build_approval.runtime_identity",
        return_value=(c.identity.account_id, c.identity.region),
    ):
        return service.inspect(SimpleNamespace(organization_id="fixture"), c.request["job_id"], **args)


def test_image_signature_approval_and_key_state_are_bound_together(context):
    c = context
    service, args, approvals = combined(c)
    result = invoke(c, service, args)
    assert result["ecr_image_verified"] and result["image_signature_approval_binding_matched"]
    assert result["signature_verified"] and result["consumed_deployment_approval_matched"]
    assert result["key_liveness_checked"] and result["read_only"]
    assert not result["current_approval_verified"] and not result["recovery_authorized"]
    assert not result["image_safety_verified"] and not result["state_changed"]
    assert not result["recovery_image"]["source_provenance_verified"]
    assert approvals.expected_request.call_count == 2
    service.image_inspector.inspect.assert_called_once()


@pytest.mark.parametrize(
    "field,value",
    [
        ("organization_id", "foreign"),
        ("application_id", "foreign"),
        ("job_id", "f" * 16),
        ("incident_id", "INC-2"),
        ("boundary_id", "f" * 32),
        ("source_revision", "f" * 40),
        ("source_digest", "sha256:" + "f" * 64),
        ("config_digest", "sha256:" + "f" * 64),
        ("build_reference", "https://github.com/sangmu1126/sky-builder/actions/runs/124"),
    ],
)
def test_foreign_or_unrelated_image_registration_is_rejected_before_ecr(context, field, value):
    c = context
    service, args, _ = combined(c)
    service.image_registration = replace(service.image_registration, **{field: value})
    with pytest.raises(OSError):
        invoke(c, service, args)
    service.image_inspector.inspect.assert_not_called()


@pytest.mark.parametrize(
    "change",
    [
        "no-key",
        "no-registration",
        "no-inspector",
        "provider-failure",
        "stale",
        "wrong-digest",
        "safety-claim",
    ],
)
def test_partial_or_failed_image_inspection_never_becomes_success(context, change):
    c = context
    service, args, _ = combined(c)
    if change == "no-key":
        service.key_observer = None
    elif change == "no-registration":
        service.image_registration = None
    elif change == "no-inspector":
        service.image_inspector = None
    elif change == "provider-failure":
        service.image_inspector.inspect.side_effect = OSError("private-provider-diagnostic")
    else:
        receipt = service.image_inspector.inspect.return_value
        if change == "stale":
            receipt["observed_at"] = (NOW - timedelta(seconds=1)).isoformat()
        elif change == "wrong-digest":
            receipt["config_digest"] = "sha256:" + "f" * 64
        else:
            receipt["image_safety_verified"] = True
    with pytest.raises(OSError) as exc:
        invoke(c, service, args)
    assert "private-provider-diagnostic" not in str(exc.value)


def test_image_read_cannot_hide_concurrent_incident_revision_change(context):
    c = context
    service, args, _ = combined(c)

    def changed(*_, **kw):
        service.scope._scope.return_value = SimpleNamespace(record={}, revision=8)
        kw["guard"]()

    service.image_inspector.inspect.side_effect = changed
    with pytest.raises(RecordConflict):
        invoke(c, service, args)
