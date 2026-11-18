"""AWS and operator-file runtime secrets are exact, pinned and short-lived."""

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from adapters.runtime.environment_secrets import (
    AwsAndPrivateEnvironmentSecretResolver,
    ControlRuntimeSecretMaterial,
    DatabaseRuntimeSecretMaterial,
    RegisteredAwsEnvironmentSecret,
    RouterTransportSecretMaterial,
    private_router_transport_registration,
)
from tests.unit.test_environment_admission import registered

ACCOUNT = "111111111111"
REGION = "ap-northeast-2"
PURPOSES = (
    "entrypoint_probe",
    "source_control",
    "source_database",
    "target_control",
    "target_database",
)


def private_files(tmp_path):
    key, hosts = tmp_path / "id", tmp_path / "hosts"
    key.write_text("private-key-material")
    hosts.write_text("host.test ssh-ed25519 AAAA")
    key.chmod(0o600)
    hosts.chmod(0o600)
    return key, hosts


def aws_target(purpose, index):
    return RegisteredAwsEnvironmentSecret(
        purpose,
        "secret-" + purpose,
        format(index + 1, "032x"),
        f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:sky-{purpose}-abc123",
        (("sky-application-id", "app"), ("sky-managed", "true")),
    )


def fixture(tmp_path):
    execution = registered()
    targets = tuple(aws_target(purpose, index) for index, purpose in enumerate(PURPOSES))
    key, hosts = private_files(tmp_path)
    router = private_router_transport_registration("secret-router", key, hosts)
    sts = Mock(get_caller_identity=Mock(return_value={"Account": ACCOUNT}))
    secrets = Mock(meta=SimpleNamespace(region_name=REGION))

    def describe(SecretId):
        target = next(value for value in targets if value.secret_arn == SecretId)
        return {
            "ARN": target.secret_arn,
            "Tags": [
                {"Key": "sky-managed", "Value": "true"},
                {"Key": "sky-application-id", "Value": "app"},
            ],
        }

    def get(SecretId, VersionId):
        target = next(value for value in targets if value.secret_arn == SecretId)
        assert VersionId == target.version_ref
        value = (
            {"username": "sky_transfer_user", "password": "private-password"}
            if target.purpose.endswith("database")
            else {"token": "private-control-token"}
        )
        return {"ARN": SecretId, "VersionId": VersionId, "SecretString": json.dumps(value)}

    secrets.describe_secret.side_effect = describe
    secrets.get_secret_value.side_effect = get
    resolver = AwsAndPrivateEnvironmentSecretResolver(
        execution_revision=execution.revision,
        account_id=ACCOUNT,
        region=REGION,
        aws_secrets=targets,
        router_transport=router,
        sts=sts,
        secretsmanager=secrets,
    )
    return execution, targets, router, sts, secrets, resolver


@pytest.mark.parametrize("purpose", PURPOSES)
def test_exact_aws_secret_version_returns_typed_redacted_material(tmp_path, purpose):
    execution, targets, _router, sts, secrets, resolver = fixture(tmp_path)
    target = next(value for value in targets if value.purpose == purpose)
    guard = Mock()
    with resolver.open(
        target.secret_ref,
        target.version_ref,
        execution=execution,
        purpose=purpose,
        guard=guard,
    ) as material:
        expected = (
            DatabaseRuntimeSecretMaterial if purpose.endswith("database") else ControlRuntimeSecretMaterial
        )
        assert isinstance(material, expected)
        assert "private" not in repr(material)
    sts.get_caller_identity.assert_called_once_with()
    secrets.get_secret_value.assert_called_once_with(SecretId=target.secret_arn, VersionId=target.version_ref)
    assert guard.call_count == 2


def test_router_files_are_hash_pinned_materialized_and_removed(tmp_path):
    execution, _targets, router, _sts, _secrets, resolver = fixture(tmp_path)
    with resolver.open(
        router.secret_ref,
        router.version_ref,
        execution=execution,
        purpose="router_transport",
        guard=Mock(),
    ) as material:
        assert isinstance(material, RouterTransportSecretMaterial)
        paths = (material.private_key, material.known_hosts)
        assert all(path.is_file() and stat_mode(path) == 0o600 for path in paths)
        assert all(tmp_path not in path.parents for path in paths)
    assert all(not path.exists() for path in paths)


def stat_mode(path):
    return path.stat().st_mode & 0o777


@pytest.mark.parametrize("change", ["account", "metadata", "version", "schema", "binary", "exception"])
def test_aws_identity_version_schema_or_provider_failure_is_sanitized(tmp_path, change):
    execution, targets, _router, sts, secrets, resolver = fixture(tmp_path)
    target = targets[0]
    if change == "account":
        sts.get_caller_identity.return_value = {"Account": "222222222222"}
    elif change == "metadata":
        secrets.describe_secret.side_effect = None
        secrets.describe_secret.return_value = {"ARN": target.secret_arn, "Tags": []}
    elif change == "version":
        secrets.get_secret_value.side_effect = None
        secrets.get_secret_value.return_value = {
            "ARN": target.secret_arn,
            "VersionId": "f" * 32,
            "SecretString": '{"token":"private"}',
        }
    elif change == "schema":
        secrets.get_secret_value.side_effect = None
        secrets.get_secret_value.return_value = {
            "ARN": target.secret_arn,
            "VersionId": target.version_ref,
            "SecretString": '{"token":"private","extra":true}',
        }
    elif change == "binary":
        secrets.get_secret_value.side_effect = None
        secrets.get_secret_value.return_value = {
            "ARN": target.secret_arn,
            "VersionId": target.version_ref,
            "SecretBinary": b"private",
        }
    else:
        secrets.describe_secret.side_effect = RuntimeError("private provider detail")
    with (
        pytest.raises(OSError, match="runtime secret unavailable") as error,
        resolver.open(
            target.secret_ref,
            target.version_ref,
            execution=execution,
            purpose=target.purpose,
            guard=Mock(),
        ),
    ):
        pass
    assert "private" not in str(error.value)


def test_private_file_drift_permissions_and_target_mismatch_are_rejected(tmp_path):
    execution, targets, router, _sts, _secrets, resolver = fixture(tmp_path)
    router.private_key.write_text("changed")
    with (
        pytest.raises(OSError),
        resolver.open(
            router.secret_ref,
            router.version_ref,
            execution=execution,
            purpose="router_transport",
            guard=Mock(),
        ),
    ):
        pass

    router.known_hosts.chmod(0o644)
    with (
        pytest.raises(OSError),
        resolver.open(
            router.secret_ref,
            router.version_ref,
            execution=execution,
            purpose="router_transport",
            guard=Mock(),
        ),
    ):
        pass

    target = targets[0]
    with (
        pytest.raises(ValueError, match="differs"),
        resolver.open(
            target.secret_ref,
            "f" * 32,
            execution=execution,
            purpose=target.purpose,
            guard=Mock(),
        ),
    ):
        pass


def test_resolver_reference_changes_with_version_tags_or_router_files(tmp_path):
    execution, targets, router, sts, secrets, resolver = fixture(tmp_path)
    changed = replace(targets[0], version_ref="f" * 32)
    other = AwsAndPrivateEnvironmentSecretResolver(
        execution_revision=execution.revision,
        account_id=ACCOUNT,
        region=REGION,
        aws_secrets=(changed, *targets[1:]),
        router_transport=router,
        sts=sts,
        secretsmanager=secrets,
    )
    assert resolver.reference.startswith("ESR-")
    assert other.reference != resolver.reference
    assert "private-password" not in resolver.reference


def test_registration_rejects_public_or_symlinked_operator_files(tmp_path):
    key, hosts = private_files(tmp_path)
    key.chmod(0o644)
    with pytest.raises(ValueError):
        private_router_transport_registration("secret-router", key, hosts)
    key.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(key)
    with pytest.raises(ValueError):
        private_router_transport_registration("secret-router", link, hosts)


def test_private_file_hash_uses_exact_bytes(tmp_path):
    key, hosts = private_files(tmp_path)
    registration = private_router_transport_registration("secret-router", key, hosts)
    assert registration.private_key_sha256 == hashlib.sha256(key.read_bytes()).hexdigest()
    assert registration.known_hosts_sha256 == hashlib.sha256(hosts.read_bytes()).hexdigest()
