"""Pinned AWS and operator-file secrets for environment transfer providers."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from contextlib import contextmanager, suppress
from dataclasses import asdict, dataclass, field
from pathlib import Path

from application.environment_admission import RegisteredEnvironmentExecution
from domain.environment_transition import _digest, _ref

_AWS_PURPOSES = {
    "entrypoint_probe",
    "source_control",
    "source_database",
    "target_control",
    "target_database",
}
_VERSION = re.compile(r"[A-Za-z0-9-]{32,64}\Z")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate secret field")
        result[key] = value
    return result


def _bounded_secret_document(raw):
    if not isinstance(raw, str) or not 1 <= len(raw.encode()) <= 65536:
        raise ValueError("Bounded secret string required")
    value = json.loads(raw, object_pairs_hook=_unique)
    if not isinstance(value, dict):
        raise TypeError("Secret JSON object required")
    return value


def _secret_value(value, name, *, maximum):
    result = value.get(name)
    if (
        not isinstance(result, str)
        or not 1 <= len(result.encode()) <= maximum
        or "\x00" in result
        or "\r" in result
        or "\n" in result
    ):
        raise ValueError("Bounded secret value required")
    return result


@dataclass(frozen=True)
class DatabaseRuntimeSecretMaterial:
    username: str = field(repr=False)
    password: str = field(repr=False)

    def __post_init__(self):
        _secret_value({"value": self.username}, "value", maximum=128)
        _secret_value({"value": self.password}, "value", maximum=4096)


@dataclass(frozen=True)
class ControlRuntimeSecretMaterial:
    token: str = field(repr=False)

    def __post_init__(self):
        _secret_value({"value": self.token}, "value", maximum=4096)


@dataclass(frozen=True)
class RouterTransportSecretMaterial:
    private_key: Path = field(repr=False)
    known_hosts: Path = field(repr=False)
    private_key_sha256: str
    known_hosts_sha256: str

    def __post_init__(self):
        _digest(self.private_key_sha256)
        _digest(self.known_hosts_sha256)
        if not all(
            isinstance(value, Path) and value.is_absolute() for value in (self.private_key, self.known_hosts)
        ):
            raise ValueError("Absolute materialized router transport files required")


@dataclass(frozen=True)
class RegisteredAwsEnvironmentSecret:
    purpose: str
    secret_ref: str
    version_ref: str
    secret_arn: str
    required_tags: tuple[tuple[str, str], ...]

    def __post_init__(self):
        if self.purpose not in _AWS_PURPOSES:
            raise ValueError("AWS environment secret purpose required")
        _ref(self.secret_ref)
        if not isinstance(self.version_ref, str) or not _VERSION.fullmatch(self.version_ref):
            raise ValueError("Immutable AWS secret version required")
        if not isinstance(self.secret_arn, str) or not re.fullmatch(
            r"arn:aws:secretsmanager:[a-z]{2}(?:-[a-z]+)+-\d+:\d{12}:secret:[A-Za-z0-9/_+=.@-]{1,512}",
            self.secret_arn,
        ):
            raise ValueError("Canonical AWS secret ARN required")
        if (
            not isinstance(self.required_tags, tuple)
            or tuple(sorted(self.required_tags)) != self.required_tags
            or len(dict(self.required_tags)) != len(self.required_tags)
            or dict(self.required_tags).get("sky-managed") != "true"
            or any(
                not isinstance(key, str)
                or not isinstance(value, str)
                or not key
                or not value
                or len(key) > 128
                or len(value) > 256
                for key, value in self.required_tags
            )
        ):
            raise ValueError("Canonical owned AWS secret tags required")


def _private_file(path, expected_sha256=None):
    value = Path(path)
    if expected_sha256 is not None:
        _digest(expected_sha256)
    if not value.is_absolute() or value.is_symlink():
        raise ValueError("Absolute plain operator secret file required")
    descriptor = os.open(value, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.getuid()
            or not 1 <= before.st_size <= 1024 * 1024
        ):
            raise ValueError("Operator secret file ownership or mode differs")
        content = bytearray()
        while len(content) <= 1024 * 1024:
            chunk = os.read(descriptor, min(65536, 1024 * 1024 + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        if len(content) != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("Operator secret file changed")
        if expected_sha256 is not None and hashlib.sha256(content).hexdigest() != expected_sha256:
            raise ValueError("Operator secret file changed")
        return bytes(content)
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class RegisteredPrivateRouterTransportSecret:
    secret_ref: str
    version_ref: str
    private_key: Path
    known_hosts: Path
    private_key_sha256: str
    known_hosts_sha256: str

    def __post_init__(self):
        _ref(self.secret_ref)
        _digest(self.private_key_sha256)
        _digest(self.known_hosts_sha256)
        if not all(
            isinstance(value, Path) and value.is_absolute() for value in (self.private_key, self.known_hosts)
        ):
            raise ValueError("Absolute registered router transport files required")
        expected = hashlib.sha256(
            json.dumps(
                {
                    "profile": "private-router-transport-v1",
                    "private_key_sha256": self.private_key_sha256,
                    "known_hosts_sha256": self.known_hosts_sha256,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        if self.version_ref != "files-" + expected:
            raise ValueError("Router transport version differs from registered files")


def private_router_transport_registration(secret_ref, private_key, known_hosts):
    key_path, hosts_path = Path(private_key), Path(known_hosts)
    key = _private_file(key_path)
    hosts = _private_file(hosts_path)
    key_digest, hosts_digest = hashlib.sha256(key).hexdigest(), hashlib.sha256(hosts).hexdigest()
    version = hashlib.sha256(
        json.dumps(
            {
                "profile": "private-router-transport-v1",
                "private_key_sha256": key_digest,
                "known_hosts_sha256": hosts_digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return RegisteredPrivateRouterTransportSecret(
        secret_ref,
        "files-" + version,
        key_path,
        hosts_path,
        key_digest,
        hosts_digest,
    )


class AwsAndPrivateEnvironmentSecretResolver:
    def __init__(
        self,
        *,
        execution_revision,
        account_id,
        region,
        aws_secrets,
        router_transport,
        sts,
        secretsmanager,
    ):
        if not isinstance(execution_revision, str) or not re.fullmatch(r"[a-f0-9]{64}", execution_revision):
            raise ValueError("Exact environment execution revision required")
        if not isinstance(account_id, str) or not re.fullmatch(r"\d{12}", account_id):
            raise ValueError("Canonical AWS account required")
        if not isinstance(region, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d+", region):
            raise ValueError("Canonical AWS region required")
        if (
            not isinstance(aws_secrets, tuple)
            or not all(isinstance(value, RegisteredAwsEnvironmentSecret) for value in aws_secrets)
            or tuple(value.purpose for value in aws_secrets) != tuple(sorted(_AWS_PURPOSES))
            or len({value.secret_ref for value in aws_secrets}) != len(aws_secrets)
            or not isinstance(router_transport, RegisteredPrivateRouterTransportSecret)
            or router_transport.secret_ref in {value.secret_ref for value in aws_secrets}
        ):
            raise ValueError("Canonical environment secret targets required")
        prefix = f"arn:aws:secretsmanager:{region}:{account_id}:secret:"
        if any(not value.secret_arn.startswith(prefix) for value in aws_secrets):
            raise ValueError("Environment secrets must belong to the registered account and region")
        if not callable(getattr(sts, "get_caller_identity", None)) or not all(
            callable(getattr(secretsmanager, name, None)) for name in ("describe_secret", "get_secret_value")
        ):
            raise TypeError("Read-only AWS secret clients required")
        client_region = getattr(getattr(secretsmanager, "meta", None), "region_name", None)
        if client_region != region:
            raise ValueError("AWS secret client region differs from registration")
        self.execution_revision = execution_revision
        self.account_id, self.region = account_id, region
        self.targets = {value.secret_ref: value for value in (*aws_secrets, router_transport)}
        self.router_transport = router_transport
        self.sts, self.secretsmanager = sts, secretsmanager
        document = {
            "schema_version": 1,
            "profile": "aws_private_environment_secret_resolver_v1",
            "execution_revision": execution_revision,
            "account_id": account_id,
            "region": region,
            "aws_secrets": [asdict(value) for value in aws_secrets],
            "router_transport": {
                "secret_ref": router_transport.secret_ref,
                "version_ref": router_transport.version_ref,
                "private_key_sha256": router_transport.private_key_sha256,
                "known_hosts_sha256": router_transport.known_hosts_sha256,
            },
        }
        self.reference = (
            "ESR-"
            + hashlib.sha256(
                json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            ).hexdigest()
        )

    def _aws_material(self, target):
        if self.sts.get_caller_identity().get("Account") != self.account_id:
            raise ValueError("AWS secret authority changed")
        metadata = self.secretsmanager.describe_secret(SecretId=target.secret_arn)
        tags = {value.get("Key"): value.get("Value") for value in metadata.get("Tags", [])}
        if (
            metadata.get("ARN") != target.secret_arn
            or metadata.get("DeletedDate") is not None
            or any(tags.get(key) != value for key, value in target.required_tags)
        ):
            raise ValueError("AWS secret ownership changed")
        response = self.secretsmanager.get_secret_value(
            SecretId=target.secret_arn,
            VersionId=target.version_ref,
        )
        if (
            response.get("ARN") != target.secret_arn
            or response.get("VersionId") != target.version_ref
            or "SecretString" not in response
            or "SecretBinary" in response
        ):
            raise ValueError("AWS secret version changed")
        value = _bounded_secret_document(response["SecretString"])
        if target.purpose.endswith("database"):
            if set(value) != {"username", "password"}:
                raise ValueError("Exact database credential schema required")
            return DatabaseRuntimeSecretMaterial(
                _secret_value(value, "username", maximum=128),
                _secret_value(value, "password", maximum=4096),
            )
        if set(value) != {"token"}:
            raise ValueError("Exact controller token schema required")
        return ControlRuntimeSecretMaterial(_secret_value(value, "token", maximum=4096))

    @contextmanager
    def _router_material(self, target):
        key = _private_file(target.private_key, target.private_key_sha256)
        hosts = _private_file(target.known_hosts, target.known_hosts_sha256)
        directory = Path(tempfile.mkdtemp(prefix="sky-environment-router-"))
        directory.chmod(0o700)
        private_key, known_hosts = directory / "identity", directory / "known_hosts"
        try:
            for path, content in ((private_key, key), (known_hosts, hosts)):
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, "wb") as output:
                    output.write(content)
                    output.flush()
                    os.fsync(output.fileno())
            yield RouterTransportSecretMaterial(
                private_key,
                known_hosts,
                target.private_key_sha256,
                target.known_hosts_sha256,
            )
        finally:
            shutil.rmtree(directory)

    @contextmanager
    def open(self, secret_ref, version_ref, *, execution, purpose, guard):
        if (
            not isinstance(execution, RegisteredEnvironmentExecution)
            or execution.revision != self.execution_revision
            or not callable(guard)
        ):
            raise ValueError("Exact guarded environment secret execution required")
        target = self.targets.get(secret_ref)
        expected_purpose = (
            "router_transport"
            if isinstance(target, RegisteredPrivateRouterTransportSecret)
            else getattr(target, "purpose", None)
        )
        if target is None or target.version_ref != version_ref or expected_purpose != purpose:
            raise ValueError("Environment secret target differs from registration")
        if isinstance(target, RegisteredAwsEnvironmentSecret):
            try:
                guard()
                material = self._aws_material(target)
                guard()
            except Exception:  # noqa: BLE001 -- keep AWS secret details private
                raise OSError("Registered environment runtime secret unavailable") from None
            yield material
            return
        manager = self._router_material(target)
        try:
            guard()
            material = manager.__enter__()
            guard()
        except Exception:  # noqa: BLE001 -- keep private file details and paths private
            with suppress(Exception):
                manager.__exit__(None, None, None)
            raise OSError("Registered environment runtime secret unavailable") from None
        try:
            yield material
        finally:
            manager.__exit__(None, None, None)
