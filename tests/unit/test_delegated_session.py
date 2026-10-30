import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock, patch

import pytest

from adapters.aws.delegated_session import AppRoleRegistration, ScopedAppSession, assume_app_session

NOW = datetime(2026, 10, 30, tzinfo=UTC)


def registration():
    return AppRoleRegistration(
        "personal",
        "app-a",
        "123456789012",
        "ap-northeast-2",
        "arn:aws:iam::123456789012:user/operator",
        "arn:aws:iam::123456789012:role/sky-app-a",
        "AROA" + "A" * 17,
        "external-" + "a" * 32,
        (NOW + timedelta(hours=1)).isoformat(),
        json.dumps(
            [
                {
                    "Effect": "Allow",
                    "Action": ["secretsmanager:GetSecretValue"],
                    "Resource": ["arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:app-a-AbCdEf"],
                }
            ]
        ),
        "arn:aws:iam::123456789012:policy/sky-app-a-boundary",
    )


def test_foreign_app_is_refused_before_any_sts_call():
    source = Mock()
    with pytest.raises(PermissionError, match="another"):
        assume_app_session(
            registration(),
            source,
            organization_id="personal",
            application_id="app-b",
            guard=Mock(),
            clock=lambda: NOW,
        )
    source.client.assert_not_called()


def test_pinned_role_session_is_short_lived_and_never_uses_ambient_credentials():
    r = registration()
    source = Mock()
    sts = source.client.return_value
    sts.get_caller_identity.return_value = {"Account": r.account_id, "Arn": r.source_principal_arn}
    source.client.return_value.get_role.return_value = {
        "Role": {
            "RoleId": r.role_id,
            "Arn": r.role_arn,
            "PermissionsBoundary": {"PermissionsBoundaryArn": r.boundary_arn},
        }
    }
    sts.assume_role.return_value = {
        "AssumedRoleUser": {
            "AssumedRoleId": r.role_id + ":test",
            "Arn": "arn:aws:sts::123456789012:assumed-role/sky-app-a/test",
        },
        "Credentials": {
            "AccessKeyId": "synthetic-access",
            "SecretAccessKey": "synthetic-secret",
            "SessionToken": "synthetic-session",
            "Expiration": NOW + timedelta(minutes=15),
        },
    }
    with patch("boto3.Session") as factory:
        scoped = assume_app_session(
            r, source, organization_id="personal", application_id="app-a", guard=Mock(), clock=lambda: NOW
        )
    assert isinstance(scoped, ScopedAppSession)
    assert factory.call_args.kwargs["aws_session_token"] == "synthetic-session"
    args = sts.assume_role.call_args.kwargs
    assert args["DurationSeconds"] == 900 and args["ExternalId"] == r.external_id
    assert (
        json.loads(args["Policy"])["Statement"][0]["Resource"] == json.loads(r.statements_json)[0]["Resource"]
    )


def test_all_sdk_calls_recheck_guard_and_expiry_without_refreshing():
    r = registration()
    raw = Mock()
    guard = Mock()
    clock = Mock(return_value=NOW)
    scoped = ScopedAppSession(raw, r, NOW + timedelta(minutes=15), guard, clock)
    client = scoped.client("secretsmanager")
    callback = client.meta.events.register.call_args.args[1]
    guard.side_effect = PermissionError("revoked")
    with pytest.raises(PermissionError, match="revoked"):
        callback()
    guard.side_effect = None
    clock.return_value = NOW + timedelta(minutes=16)
    with pytest.raises(PermissionError, match="expired"):
        callback()
    with pytest.raises(PermissionError):
        scoped.client("secretsmanager")


def test_foreign_region_and_unbounded_policy_are_rejected():
    r = registration()
    with pytest.raises(ValueError):
        replace(
            r,
            statements_json=json.dumps(
                [{"Effect": "Allow", "Action": ["iam:CreateRole"], "Resource": ["*"]}]
            ),
        )
    scoped = ScopedAppSession(Mock(), r, NOW + timedelta(minutes=15), Mock(), lambda: NOW)
    with pytest.raises(PermissionError, match="region"):
        scoped.client("secretsmanager", region_name="us-east-1")


def test_source_identity_mismatch_cannot_assume_role():
    r = registration()
    source = Mock()
    source.client.return_value.get_caller_identity.return_value = {
        "Account": r.account_id,
        "Arn": r.source_principal_arn + "-foreign",
    }
    with pytest.raises(PermissionError, match="source identity"):
        assume_app_session(
            r, source, organization_id="personal", application_id="app-a", guard=Mock(), clock=lambda: NOW
        )
    source.client.return_value.assume_role.assert_not_called()


def test_kms_permission_cannot_escape_secret_encryption_context():
    r = registration()
    statements = json.loads(r.statements_json)
    key = "arn:aws:kms:ap-northeast-2:123456789012:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    decrypt = {
        "Effect": "Allow",
        "Action": ["kms:Decrypt"],
        "Resource": [key],
        "Condition": {
            "StringEquals": {
                "kms:ViaService": "secretsmanager.ap-northeast-2.amazonaws.com",
                "kms:EncryptionContext:SecretARN": statements[0]["Resource"],
            }
        },
    }
    limited = replace(r, statements_json=json.dumps([*statements, decrypt]))
    assert "kms:ViaService" in limited.policy()
    decrypt["Condition"]["StringEquals"]["kms:ViaService"] = "*"
    with pytest.raises(ValueError, match="Secret context"):
        replace(r, statements_json=json.dumps([*statements, decrypt]))


def test_client_cannot_replace_credentials_or_bypass_transport():
    scoped = ScopedAppSession(Mock(), registration(), NOW + timedelta(minutes=15), Mock(), lambda: NOW)
    for kwargs in (
        {"aws_access_key_id": "synthetic"},
        {"endpoint_url": "http://localhost"},
        {"verify": False},
    ):
        with pytest.raises(ValueError, match="override"):
            scoped.client("secretsmanager", **kwargs)


def test_issuance_uses_fresh_clock_and_rejects_expired_approval():
    r = registration()
    source = Mock()
    sts = source.client.return_value
    sts.get_caller_identity.return_value = {"Account": r.account_id, "Arn": r.source_principal_arn}
    sts.get_role.return_value = {
        "Role": {
            "RoleId": r.role_id,
            "Arn": r.role_arn,
            "PermissionsBoundary": {"PermissionsBoundaryArn": r.boundary_arn},
        }
    }
    issued = NOW + timedelta(seconds=10)
    sts.assume_role.return_value = {
        "AssumedRoleUser": {
            "AssumedRoleId": r.role_id + ":test",
            "Arn": "arn:aws:sts::123456789012:assumed-role/sky-app-a/test",
        },
        "Credentials": {
            "AccessKeyId": "synthetic",
            "SecretAccessKey": "synthetic",
            "SessionToken": "synthetic",
            "Expiration": issued + timedelta(minutes=15),
        },
    }
    with patch("boto3.Session"):
        scoped = assume_app_session(
            r,
            source,
            organization_id="personal",
            application_id="app-a",
            guard=Mock(),
            clock=Mock(side_effect=[NOW, issued]),
        )
    assert scoped.expiry == issued + timedelta(minutes=15)
    with pytest.raises(PermissionError, match="lifetime"):
        assume_app_session(
            r,
            source,
            organization_id="personal",
            application_id="app-a",
            guard=Mock(),
            clock=Mock(side_effect=[NOW, NOW + timedelta(hours=1)]),
        )
