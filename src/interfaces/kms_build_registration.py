"""Operator-owned public trust and input pins, never uploaded project settings."""

import base64
import json
import re
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm

from application.kms_build_signature import KmsBuildSigningIdentity
from ports.remote_builds import BuildSettings, canonical


def document(path, limit=65536):
    with Path(path).open("rb") as stream:
        raw = stream.read(limit + 1)
    if not raw or len(raw) > limit:
        raise ValueError("Operator build registration exceeds bound")
    value = json.loads(raw)
    if raw != canonical(value):
        raise ValueError("Canonical operator build registration required")
    return value


def load_identity(path):
    value = document(path, 4096)
    if (
        not isinstance(value, dict)
        or set(value) != {"version", "key_arn", "public_key_der"}
        or type(value["version"]) is not int
        or value["version"] != 1
        or not isinstance(value["public_key_der"], str)
    ):
        raise ValueError("Exact operator KMS public trust registration required")
    raw = base64.b64decode(value["public_key_der"], validate=True)
    if base64.b64encode(raw).decode() != value["public_key_der"]:
        raise ValueError("Canonical public trust encoding required")
    try:
        return KmsBuildSigningIdentity(value["key_arn"], raw)
    except UnsupportedAlgorithm:
        raise ValueError("Supported public trust key required") from None


@dataclass(frozen=True)
class BuildApprovalRegistration:
    identity: KmsBuildSigningIdentity
    settings: BuildSettings
    bundle: dict
    image_digest: str
    config_digest: str
    run_id: int


def load_build_approval_registration(path):
    if not path:
        raise ValueError("Explicit operator build approval registration required")
    value = document(path, 16384)
    if (
        not isinstance(value, dict)
        or set(value)
        != {"version", "key_config", "builder", "bundle", "image_digest", "config_digest", "run_id"}
        or type(value["version"]) is not int
        or value["version"] != 1
        or not isinstance(value["builder"], dict)
        or set(value["builder"]) != set(BuildSettings.__dataclass_fields__)
    ):
        raise ValueError("Exact versioned build approval registration required")

    def local_file(name):
        candidate = value[name]
        if not isinstance(candidate, str) or not candidate or len(candidate) > 4096 or "\x00" in candidate:
            raise ValueError("Explicit operator file path required")
        candidate = Path(candidate)
        return candidate if candidate.is_absolute() else Path(path).resolve().parent / candidate

    identity = load_identity(local_file("key_config"))
    settings = BuildSettings(**value["builder"])
    if (identity.account_id, identity.region) != (settings.account_id, settings.region):
        raise ValueError("Signer and registered builder scope differ")
    for name in ("image_digest", "config_digest"):
        if not isinstance(value[name], str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", value[name]):
            raise ValueError("Immutable image and config pins required")
    if type(value["run_id"]) is not int or not 0 < value["run_id"] < 10**20:
        raise ValueError("Exact build run pin required")
    bundle = document(local_file("bundle"))
    if not isinstance(bundle, dict) or set(bundle) != {"payload", "signature"}:
        raise ValueError("Exact signed build envelope required")
    return BuildApprovalRegistration(
        identity, settings, bundle, value["image_digest"], value["config_digest"], value["run_id"]
    )
