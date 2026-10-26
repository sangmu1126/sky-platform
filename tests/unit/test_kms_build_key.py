from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from adapters.aws.kms_build_key import AwsKmsBuildKeyObserver
from tests.unit.test_incident_build_approval import invoke, setup
from tests.unit.test_kms_build_signature import NOW
from tests.unit.test_kms_build_signature import context as context  # noqa: PLC0414


def native(identity, clock=lambda: NOW):
    kms = Mock(spec=["meta", "describe_key", "get_public_key"])
    sts = Mock(spec=["meta", "get_caller_identity"])
    for client in (kms, sts):
        client.meta = SimpleNamespace(region_name=identity.region)
    sts.get_caller_identity.return_value = {"Account": identity.account_id}
    kms.describe_key.return_value = {
        "KeyMetadata": {
            "Arn": identity.key_arn,
            "KeyId": identity.key_arn.rsplit("/", 1)[1],
            "AWSAccountId": identity.account_id,
            "KeyState": "Enabled",
            "Enabled": True,
            "KeyUsage": "SIGN_VERIFY",
            "KeySpec": "ECC_NIST_P256",
            "Origin": "AWS_KMS",
            "KeyManager": "CUSTOMER",
            "MultiRegion": False,
        }
    }
    kms.get_public_key.return_value = {
        "KeyId": identity.key_arn,
        "PublicKey": identity.public_key_der,
        "KeyUsage": "SIGN_VERIFY",
        "KeySpec": "ECC_NIST_P256",
        "SigningAlgorithms": ["ECDSA_SHA_256"],
    }
    session = Mock(client=lambda name, **kw: {"kms": kms, "sts": sts}[name])
    return AwsKmsBuildKeyObserver(identity, session=session, clock=clock), session, kms, sts


def test_enabled_registered_key_is_a_read_only_observation(context):
    observer, _, kms, sts = native(context.identity)
    receipt = observer.observe(guard=Mock())
    assert receipt["key_liveness_checked"] and receipt["read_only"]
    assert not receipt["revocation_race_excluded"] and not receipt["key_policy_audited"]
    assert not receipt["state_changed"] and not receipt["recovery_authorized"]
    assert kms.describe_key.call_count == 2 and kms.get_public_key.call_count == 1
    assert sts.get_caller_identity.call_count == 1
    assert all(call.kwargs == {"KeyId": context.identity.key_arn} for call in kms.mock_calls)


@pytest.mark.parametrize(
    "change",
    [
        "Disabled",
        "PendingDeletion",
        "Unavailable",
        "account",
        "region",
        "arn",
        "key-id",
        "usage",
        "spec",
        "origin",
        "manager",
        "multi",
        "enabled",
        "public",
        "algorithm",
    ],
)
def test_disabled_foreign_or_changed_key_is_rejected(context, change):
    observer, _, kms, sts = native(context.identity)
    meta = kms.describe_key.return_value["KeyMetadata"]
    if change in {"Disabled", "PendingDeletion", "Unavailable"}:
        meta["KeyState"] = change
        meta["Enabled"] = False
    elif change == "account":
        sts.get_caller_identity.return_value["Account"] = "222222222222"
    elif change == "region":
        kms.meta.region_name = "us-east-1"
    elif change == "public":
        kms.get_public_key.return_value["PublicKey"] = b"different"
    elif change == "algorithm":
        kms.get_public_key.return_value["SigningAlgorithms"] = ["ECDSA_SHA_384"]
    else:
        key, value = {
            "arn": ("Arn", "foreign"),
            "key-id": ("KeyId", "foreign"),
            "usage": ("KeyUsage", "ENCRYPT_DECRYPT"),
            "spec": ("KeySpec", "ECC_NIST_P384"),
            "origin": ("Origin", "EXTERNAL"),
            "manager": ("KeyManager", "AWS"),
            "multi": ("MultiRegion", True),
            "enabled": ("Enabled", 1),
        }[change]
        meta[key] = value
    with pytest.raises(ValueError):
        observer.observe(guard=lambda: None)


def test_key_disabled_between_reads_is_rejected(context):
    observer, _, kms, _ = native(context.identity)
    enabled = deepcopy(kms.describe_key.return_value)
    disabled = deepcopy(enabled)
    disabled["KeyMetadata"].update(KeyState="Disabled", Enabled=False)
    kms.describe_key.side_effect = [enabled, disabled]
    with pytest.raises(ValueError):
        observer.observe(guard=lambda: None)


def test_key_observation_revocation_guard_stops_further_calls(context):
    observer, _, kms, _ = native(context.identity)
    revoked = False

    def described(**_):
        nonlocal revoked
        revoked = True
        return kms.describe_key.return_value

    def guard():
        if revoked:
            raise PermissionError("Administrator revoked")

    kms.describe_key.side_effect = described
    with pytest.raises(PermissionError):
        observer.observe(guard=guard)
    kms.get_public_key.assert_not_called()


def test_incident_inspection_includes_current_key_snapshot_only(context):
    c = context
    service, args, _ = setup(c)
    service.key_observer, _, _, _ = native(c.identity)
    receipt = invoke(c, service, args)
    assert receipt["key_liveness_checked"] and receipt["signing_key"]["key_state"] == "Enabled"
    assert not receipt["current_approval_verified"] and not receipt["recovery_authorized"]


@pytest.mark.parametrize("failure", ["denied", "disabled", "stale", "wrong-receipt", "recovery-claim"])
def test_online_failure_cannot_fall_back_to_offline_success(context, failure):
    c = context
    service, args, _ = setup(c)
    observer, _, kms, _ = native(c.identity)
    service.key_observer = observer
    if failure == "denied":
        kms.describe_key.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "private-diagnostic"}}, "DescribeKey"
        )
    elif failure == "disabled":
        kms.describe_key.return_value["KeyMetadata"].update(KeyState="Disabled", Enabled=False)
    elif failure == "stale":
        observer.clock = lambda: NOW - timedelta(seconds=1)
    else:
        receipt = observer.observe(guard=lambda: None)
        if failure == "wrong-receipt":
            receipt["public_key_fingerprint"] = "foreign"
        else:
            receipt["recovery_authorized"] = True
        service.key_observer = Mock(observe=Mock(return_value=receipt))
    with pytest.raises(OSError, match="hold and access unchanged") as exc:
        invoke(c, service, args)
    assert "private-diagnostic" not in str(exc.value)
