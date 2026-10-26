import base64
import json
from dataclasses import asdict
from unittest.mock import patch

import pytest

from interfaces.b_runtime import main
from interfaces.kms_build_registration import load_build_approval_registration
from ports.remote_builds import BuildSettings, canonical
from tests.unit.test_kms_build_signature import context as context  # noqa: PLC0414 -- pytest fixture
from tests.unit.test_kms_build_signature import signed
from tests.unit.test_security_hold_cli import arguments
from tests.unit.test_security_hold_cli import configured_cli as configured_cli  # noqa: PLC0414


@pytest.fixture
def registration(context):
    c = context
    key = c.root / "key.json"
    key.write_bytes(
        canonical(
            {
                "version": 1,
                "key_arn": c.identity.key_arn,
                "public_key_der": base64.b64encode(c.identity.public_key_der).decode(),
            }
        )
    )
    bundle = c.root / "signed.json"
    bundle.write_bytes(canonical(signed(c)))
    settings = BuildSettings(
        c.request["repository"],
        "main",
        c.request["workflow_sha"],
        c.request["platform_code_sha"],
        c.request["bucket"],
        c.request["account_id"],
        c.request["region"],
    )
    value = {
        "version": 1,
        "key_config": key.name,
        "builder": asdict(settings),
        "bundle": bundle.name,
        **c.options,
    }
    path = c.root / "inspection.json"
    path.write_bytes(canonical(value))
    return path, value


def cli(path):
    return arguments("inspect-build-approval") + [
        "--build-approval-config",
        str(path),
        "--incident-id",
        "INC-1",
        "--expected-revision",
        "7",
        "--expected-boundary",
        "b" * 32,
    ]


def test_package_loader_reads_relative_public_trust_and_pins(registration, context):
    path, value = registration
    result = load_build_approval_registration(path)
    assert result.identity == context.identity
    assert result.settings.repository == context.request["repository"]
    assert result.bundle == json.loads((path.parent / value["bundle"]).read_bytes())
    assert result.run_id == 123


def test_preflight_never_reads_database_or_creates_cloud_clients(configured_cli, registration, capsys):
    path, _ = registration
    with (
        patch("boto3.client", side_effect=AssertionError("Cloud")),
        patch("boto3.Session", side_effect=AssertionError("Cloud")),
        patch("interfaces.security_hold.RotatingDatabaseConnection", side_effect=AssertionError("Database")),
    ):
        main(cli(path) + ["--check-config"])
    assert "no AWS/DB calls" in capsys.readouterr().out


@pytest.mark.parametrize(
    "extra",
    [
        ["--confirm-hold"],
        ["--review-ref", "review"],
        ["--confirm-false-positive"],
        ["--confirm-database-restriction"],
        ["--confirm-credential-preparation"],
        ["--confirm-runtime-containment"],
        ["--confirm-secret-access-fence"],
        ["--expected-operation-id", "a" * 32],
        ["--pool-config", "unused"],
        ["--recovery-image-config", "unused"],
        ["--recovery-provenance-config", "unused"],
    ],
)
def test_readonly_action_cannot_mix_mutations(configured_cli, registration, extra):
    path, _ = registration
    with (
        patch("interfaces.security_hold.RotatingDatabaseConnection", side_effect=AssertionError("Database")),
        pytest.raises(SystemExit) as exc,
    ):
        main(cli(path) + extra + ["--check-config"])
    assert exc.value.code == 2


@pytest.mark.parametrize(
    "change",
    [
        "unknown",
        "request",
        "tag",
        "run-bool",
        "account",
        "key-swap",
        "noncanonical",
        "duplicate",
        "oversize",
        "bad-bundle",
    ],
)
def test_malformed_or_ambiguous_registration_rejected(registration, change):
    path, value = registration
    if change == "unknown":
        value["extra"] = True
    elif change == "request":
        value["expected_request"] = {}
    elif change == "tag":
        value["image_digest"] = "latest"
    elif change == "run-bool":
        value["run_id"] = True
    elif change == "account":
        value["builder"]["account_id"] = "222222222222"
    elif change == "key-swap":
        value["key_config"] = value["bundle"]
    elif change == "noncanonical":
        path.write_text(json.dumps(value, indent=2))
    elif change == "duplicate":
        path.write_bytes(canonical(value)[:-1] + b',"version":1}')
    elif change == "oversize":
        path.write_bytes(b" " * 16385)
    else:
        (path.parent / value["bundle"]).write_bytes(canonical({"payload": {}}))
    if change not in {"noncanonical", "duplicate", "oversize"}:
        path.write_bytes(canonical(value))
    with pytest.raises((ValueError, TypeError)):
        load_build_approval_registration(path)


def test_build_registration_rejected_by_other_actions(configured_cli, registration):
    path, _ = registration
    with pytest.raises(SystemExit) as exc:
        main(arguments() + ["--build-approval-config", str(path), "--check-config"])
    assert exc.value.code == 2
