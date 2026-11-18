"""AWS and operator-file runtime secrets are exact, pinned and short-lived."""

import hashlib
import json
import os
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock, patch

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
    sts = Mock(
        meta=SimpleNamespace(
            region_name=REGION,
            endpoint_url=f"https://sts.{REGION}.amazonaws.com",
        ),
        get_caller_identity=Mock(return_value={"Account": ACCOUNT}),
    )
    secrets = Mock(
        meta=SimpleNamespace(
            region_name=REGION,
            endpoint_url=f"https://secretsmanager.{REGION}.amazonaws.com",
        )
    )

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
        ca = material.private_key.parent / "source-ca.pem"
        ca.write_text("runtime-public-ca")
        ca.chmod(0o400)
        paths = (material.private_key, material.known_hosts, ca)
        assert all(path.is_file() for path in paths)
        assert all(stat_mode(path) == 0o600 for path in paths[:2])
        assert stat_mode(ca) == 0o400
        assert all(tmp_path not in path.parents for path in paths)
    assert all(not path.exists() for path in paths)


def test_router_materialization_uses_exact_modes_even_with_restrictive_umask(tmp_path):
    execution, _targets, router, _sts, _secrets, resolver = fixture(tmp_path)
    previous = os.umask(0o777)
    try:
        with resolver.open(
            router.secret_ref,
            router.version_ref,
            execution=execution,
            purpose="router_transport",
            guard=Mock(),
        ) as material:
            directory = material.private_key.parent
            paths = (material.private_key, material.known_hosts)
            assert stat_mode(directory) == 0o700
            assert all(stat_mode(path) == 0o600 for path in paths)
    finally:
        os.umask(previous)
    assert not directory.exists()


def test_router_cleanup_uses_open_directory_when_workspace_path_is_replaced(tmp_path):
    execution, _targets, router, _sts, _secrets, resolver = fixture(tmp_path)
    replacement = None
    moved = None
    with resolver.open(
        router.secret_ref,
        router.version_ref,
        execution=execution,
        purpose="router_transport",
        guard=Mock(),
    ) as material:
        directory = material.private_key.parent
        moved = directory.with_name(directory.name + "-moved")
        directory.rename(moved)
        directory.mkdir(mode=0o700)
        replacement = directory / "replacement"
        replacement.write_text("preserve")
    assert replacement.read_text() == "preserve"
    assert directory.is_dir()
    assert moved.is_dir() and not tuple(moved.iterdir())
    replacement.unlink()
    directory.rmdir()
    moved.rmdir()


def stat_mode(path):
    return path.stat().st_mode & 0o777


@pytest.mark.parametrize(
    "change",
    [
        "account",
        "identity-shape",
        "metadata",
        "metadata-shape",
        "duplicate-tags",
        "malformed-tags",
        "version",
        "version-shape",
        "schema",
        "binary",
        "exception",
    ],
)
def test_aws_identity_version_schema_or_provider_failure_is_sanitized(tmp_path, change):
    execution, targets, _router, sts, secrets, resolver = fixture(tmp_path)
    target = targets[0]
    if change == "account":
        sts.get_caller_identity.return_value = {"Account": "222222222222"}
    elif change == "identity-shape":
        sts.get_caller_identity.return_value = [ACCOUNT]
    elif change == "metadata":
        secrets.describe_secret.side_effect = None
        secrets.describe_secret.return_value = {"ARN": target.secret_arn, "Tags": []}
    elif change == "metadata-shape":
        secrets.describe_secret.side_effect = None
        secrets.describe_secret.return_value = [target.secret_arn]
    elif change == "duplicate-tags":
        secrets.describe_secret.side_effect = None
        secrets.describe_secret.return_value = {
            "ARN": target.secret_arn,
            "Tags": [
                {"Key": "sky-managed", "Value": "false"},
                {"Key": "sky-managed", "Value": "true"},
                {"Key": "sky-application-id", "Value": "app"},
            ],
        }
    elif change == "malformed-tags":
        secrets.describe_secret.side_effect = None
        secrets.describe_secret.return_value = {
            "ARN": target.secret_arn,
            "Tags": [{"Key": ["sky-managed"], "Value": "true"}],
        }
    elif change == "version":
        secrets.get_secret_value.side_effect = None
        secrets.get_secret_value.return_value = {
            "ARN": target.secret_arn,
            "VersionId": "f" * 32,
            "SecretString": '{"token":"private"}',
        }
    elif change == "version-shape":
        secrets.get_secret_value.side_effect = None
        secrets.get_secret_value.return_value = [target.secret_arn, target.version_ref]
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


@pytest.mark.parametrize(
    "change",
    ["reference", "targets", "registration", "sts-endpoint", "secrets-endpoint"],
)
def test_resolver_rechecks_registered_authority_before_secret_access(tmp_path, change):
    execution, targets, _router, sts, secrets, resolver = fixture(tmp_path)
    target = targets[0]
    if change == "reference":
        resolver.reference = "ESR-" + "f" * 64
    elif change == "targets":
        resolver.targets = {target.secret_ref: target}
    elif change == "registration":
        resolver.aws_secrets = (replace(target, version_ref="f" * 32), *targets[1:])
    elif change == "sts-endpoint":
        sts.meta.endpoint_url = "https://sts.us-east-1.amazonaws.com"
    else:
        secrets.meta.endpoint_url = "https://secretsmanager.us-east-1.amazonaws.com"
    guard = Mock()

    with (
        pytest.raises(ValueError, match="Exact guarded"),
        resolver.open(
            target.secret_ref,
            target.version_ref,
            execution=execution,
            purpose=target.purpose,
            guard=guard,
        ),
    ):
        pass
    guard.assert_not_called()
    sts.get_caller_identity.assert_not_called()
    secrets.describe_secret.assert_not_called()
    secrets.get_secret_value.assert_not_called()


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


@pytest.mark.parametrize("client", ["sts", "secretsmanager"])
def test_registration_rejects_nonregional_or_custom_aws_endpoints(tmp_path, client):
    execution, targets, router, sts, secrets, _resolver = fixture(tmp_path)
    selected = sts if client == "sts" else secrets
    selected.meta.endpoint_url = "https://localhost.invalid"
    with pytest.raises(ValueError, match="Regional AWS secret authority"):
        AwsAndPrivateEnvironmentSecretResolver(
            execution_revision=execution.revision,
            account_id=ACCOUNT,
            region=REGION,
            aws_secrets=targets,
            router_transport=router,
            sts=sts,
            secretsmanager=secrets,
        )


def test_private_file_metadata_change_during_descriptor_read_is_rejected(tmp_path):
    key, hosts = private_files(tmp_path)
    original = os.read
    changed = False

    def mutate_mode(descriptor, size):
        nonlocal changed
        content = original(descriptor, size)
        if not changed:
            os.fchmod(descriptor, 0o644)
            changed = True
        return content

    with (
        patch("adapters.runtime.environment_secrets.os.read", side_effect=mutate_mode),
        pytest.raises(ValueError, match="changed"),
    ):
        private_router_transport_registration("secret-router", key, hosts)


def test_private_file_hash_uses_exact_bytes(tmp_path):
    key, hosts = private_files(tmp_path)
    registration = private_router_transport_registration("secret-router", key, hosts)
    assert registration.private_key_sha256 == hashlib.sha256(key.read_bytes()).hexdigest()
    assert registration.known_hosts_sha256 == hashlib.sha256(hosts.read_bytes()).hexdigest()
