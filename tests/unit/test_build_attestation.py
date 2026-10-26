import hashlib
import json
from unittest.mock import patch

import pytest

from ports.remote_builds import canonical, digest
from scripts.build_attestation import prepare
from scripts.check_build_attestation import fixture


@pytest.fixture
def attestation(tmp_path):
    env = {
        "GITHUB_REPOSITORY": "sangmu1126/sky-builder",
        "GITHUB_SHA": "a" * 40,
        "SKY_PLATFORM_CODE_SHA": "b" * 40,
        "GITHUB_RUN_ID": "123",
    }
    request = fixture(tmp_path, environment=env)
    env.update(REQUEST_DIGEST=digest(request), BUILD_ID=request["build_id"])
    return tmp_path, env, request


def run(value):
    root, env, _ = value
    return prepare(root / "build-input", root / "published-proof", root / "signing-output", environment=env)


def test_minimal_signing_subjects_bind_zip_request_and_manifest_without_executing_code(attestation):
    root, _, request = attestation
    with patch("subprocess.run", side_effect=AssertionError("must not execute code or Docker")):
        result = run(attestation)
    statement = json.loads((root / "signing-output/statement.json").read_bytes())
    assert statement["source_zip_sha256"] == request["source_ref"]["sha256"]
    assert statement["source_digest"] == request["source_digest"]
    assert statement["request_digest"] == digest(request)
    assert result["statement_digest"] == "sha256:" + hashlib.sha256(canonical(statement)).hexdigest()
    assert (root / "signing-output/manifest.json").read_bytes() == (
        root / "published-proof/manifest.json"
    ).read_bytes()
    for field in ("approved_plan_json", "created_by", "source_ref", "bucket", "organization_id"):
        assert field not in statement
    assert statement["zip_and_source_digest_checked"] is True
    assert statement["faithful_compilation_verified"] is False
    assert statement["image_safety_verified"] is False and statement["recovery_authorized"] is False
    assert {p.name for p in (root / "signing-output").iterdir()} == {"manifest.json", "statement.json"}


@pytest.mark.parametrize(
    "change", ["request", "repository", "workflow", "platform", "build-id", "run", "unicode-run", "zero-run"]
)
def test_signer_rejects_wrong_caller_identity_or_run_before_output(attestation, change):
    root, env, _ = attestation
    key = {
        "request": "REQUEST_DIGEST",
        "repository": "GITHUB_REPOSITORY",
        "workflow": "GITHUB_SHA",
        "platform": "SKY_PLATFORM_CODE_SHA",
        "build-id": "BUILD_ID",
        "run": "GITHUB_RUN_ID",
        "unicode-run": "GITHUB_RUN_ID",
        "zero-run": "GITHUB_RUN_ID",
    }[change]
    env[key] = "１２３" if change == "unicode-run" else "0123" if change == "zero-run" else "wrong"
    with pytest.raises((ValueError, KeyError)):
        run(attestation)
    assert not (root / "signing-output").exists()


@pytest.mark.parametrize(
    "change", ["zip", "manifest", "result", "config", "archive", "duplicate", "source-tree"]
)
def test_signer_rejects_substituted_inputs_or_manifest(attestation, change):
    root, env, request = attestation
    if change == "zip":
        with (root / "build-input/source.zip").open("ab") as stream:
            stream.write(b"tamper")
    elif change == "manifest":
        with (root / "published-proof/manifest.json").open("ab") as stream:
            stream.write(b" ")
    elif change in {"config", "archive"}:
        path = root / "published-proof/build.json"
        value = json.loads(path.read_bytes())
        value["image_id" if change == "config" else "archive_digest"] = "wrong"
        path.write_bytes(canonical(value))
    elif change == "duplicate":
        path = root / "build-input/request.json"
        path.write_bytes(b'{"version":1,' + path.read_bytes()[1:])
    elif change == "result":
        path = root / "published-proof/result.json"
        value = json.loads(path.read_bytes())
        value["source_digest"] = "0" * 64
        path.write_bytes(canonical(value))
    else:
        # All declarations are internally consistent, but the actual normalized
        # ZIP tree still differs. A caller-controlled receipt cannot hide that.
        path = root / "build-input/request.json"
        request["source_digest"] = request["source_ref"]["source_digest"] = "0" * 64
        plan = json.loads(request["approved_plan_json"])
        plan["source_digest"] = "0" * 64
        request["approved_plan_json"] = canonical(plan).decode()
        request["plan_digest"] = digest(plan)
        path.write_bytes(canonical(request))
        env["REQUEST_DIGEST"] = digest(request)
        path = root / "published-proof/result.json"
        value = json.loads(path.read_bytes())
        value.update(
            source_digest=request["source_digest"],
            plan_digest=request["plan_digest"],
            request_digest=digest(request),
        )
        path.write_bytes(canonical(value))
        path = root / "published-proof/build.json"
        value = json.loads(path.read_bytes())
        value["request_digest"] = digest(request)
        path.write_bytes(canonical(value))
    with pytest.raises((ValueError, KeyError)):
        run(attestation)
    assert not (root / "signing-output").exists()


def test_existing_signing_output_is_never_overwritten(attestation):
    root, _, _ = attestation
    run(attestation)
    before = (root / "signing-output/statement.json").read_bytes()
    with pytest.raises(FileExistsError):
        run(attestation)
    assert (root / "signing-output/statement.json").read_bytes() == before
