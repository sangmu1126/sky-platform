"""Prevent supplied credentials from becoming part of an application image."""

from __future__ import annotations

import re
from pathlib import Path


_SENSITIVE_ENV_NAME = re.compile(
    r"(?:^|_)(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIALS?|DATABASE_URL|DB_URL|REDIS_URL|MONGODB?_URI|DSN)(?:_|$)"
)
_SENSITIVE_ENV_EXACT = {"PGPASSWORD", "MYSQL_PWD"}


def sensitive_source_path(path: Path) -> bool:
    """Exclude credential containers even when their extension looks like source.

    This is a conservative filename boundary, not content/secret detection.
    Application code such as authentication.py is intentionally not excluded.
    """
    name = path.name.casefold()
    stem = path.stem.casefold().replace("_", "-")
    return (name == ".env" or name.startswith(".env.")
            or path.suffix.casefold() in {".pem", ".key", ".p12", ".pfx", ".jks"}
            or (path.suffix.casefold() in {"", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".txt"}
                and stem in {"credentials", "credential", "secrets", "secret", "service-account",
                             "service-account-key", "id-rsa", "id-ed25519", "application-default-credentials"}))


def reject_embedded_credentials(project: Path) -> None:
    """Reject known credential containers/key formats before source storage or build.

    This is deliberately not entropy-based scanning or proof arbitrary files have
    no secrets. Values and file contents are never included in errors.
    """
    from application.deployment_core import ignored_source_path

    if not project.is_dir() or project.is_symlink():
        raise ValueError("CV-07: Deployment source must be a plain directory")
    pattern = re.compile(rb"-----BEGIN [^-\r\n]*PRIVATE KEY-----|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b|\b(?:sk-|gh[pousr]_)[A-Za-z0-9_-]{20,}\b")
    for path in project.rglob("*"):
        relative = path.relative_to(project)
        if ignored_source_path(relative):
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(project.resolve()):
            raise ValueError("CV-07: Deployment source contains an unsafe link")
        if not path.is_file():
            continue
        if sensitive_source_path(relative) and path.suffix.casefold() not in {".pem", ".key"}:
            raise ValueError("CV-07: Move credential files to managed secret references before deployment")
        try:
            with path.open("rb") as source:
                previous = b""
                while chunk := source.read(65536):
                    combined = previous + chunk
                    if pattern.search(combined):
                        raise ValueError("CV-07: Embedded credentials must be removed before deployment")
                    previous = combined[-256:]
        except OSError:
            raise ValueError("CV-07: Cannot inspect deployment source") from None


def sensitive_environment_names(environment: dict[str, str]) -> list[str]:
    """Identify supplied values that require a secret reference in a cloud target."""
    return sorted(name for name, value in environment.items()
                  if value and is_sensitive_environment_name(name))


def is_sensitive_environment_name(name: str) -> bool:
    return name in _SENSITIVE_ENV_EXACT or bool(_SENSITIVE_ENV_NAME.search(name))


def reject_plaintext_cloud_secret_names(names: list[str], target: str) -> None:
    if target in {"aws-ecs-express", "cloud-run"} and any(is_sensitive_environment_name(name) for name in names):
        raise ValueError("CV-07: Cloud deployment of supplied credentials requires SecretRef support")


def reject_plaintext_cloud_secrets(environment: dict[str, str], target: str) -> None:
    """Fail closed until the target supports secret references for user credentials."""
    reject_plaintext_cloud_secret_names(sensitive_environment_names(environment), target)


def reject_supplied_secrets_in_source(project: Path, environment: dict[str, str]) -> None:
    """Reject a supplied credential value found anywhere in the deployment source."""
    secrets = [environment[name].encode() for name in sensitive_environment_names(environment)]
    if not secrets:
        return
    for path in project.rglob("*"):
        if path.is_symlink():
            raise ValueError("CV-07: Cannot inspect a symbolic link in the deployment source")
        if not path.is_file():
            continue
        try:
            content = path.read_bytes()
        except OSError:
            raise ValueError("CV-07: Cannot inspect every deployment source file") from None
        if any(value in content for value in secrets):
            raise ValueError("CV-07: A supplied credential value appears in deployment source")
