import hashlib
import json
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from adapters.github.recovery_provenance import ISSUER, PREDICATE, GitHubRecoveryProvenance
from domain.recovery_provenance import RecoveryProvenancePolicy, expected_provenance
from interfaces.b_runtime import main
from interfaces.recovery_provenance_registration import load_recovery_provenance_registration
from tests.unit.test_recovery_image_inspection import MANIFEST, app, native, registration
from tests.unit.test_security_hold_cli import arguments

pytest_plugins = ["tests.unit.test_operating_review", "tests.unit.test_security_hold_cli"]
ROOT = b'{"test_trust_root":true}'


def policy(**changes):
    return RecoveryProvenancePolicy(
        **(
            {
                "repository": "sangmu1126/sky-platform",
                "repository_id": "123",
                "owner_id": "456",
                "signer_workflow": "trusted/builder/.github/workflows/attest.yml",
                "signer_digest": "d" * 40,
                "source_ref": "refs/heads/main",
                "trusted_root_digest": "sha256:" + hashlib.sha256(ROOT).hexdigest(),
            }
            | changes
        )
    )


def verified(r=None, p=None):
    r, p = r or registration(), p or policy()
    cert = {
        "issuer": ISSUER,
        "subjectAlternativeName": f"https://github.com/{p.signer_workflow}@{p.signer_digest}",
        "buildSignerURI": f"https://github.com/{p.signer_workflow}@{p.signer_digest}",
        "buildSignerDigest": p.signer_digest,
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryURI": f"https://github.com/{p.repository}",
        "sourceRepositoryDigest": r.source_revision,
        "sourceRepositoryRef": p.source_ref,
        "sourceRepositoryIdentifier": p.repository_id,
        "sourceRepositoryOwnerIdentifier": p.owner_id,
        "sourceRepositoryOwnerURI": "https://github.com/" + p.repository.split("/")[0],
        "runInvocationURI": r.build_reference + "/attempts/1",
    }
    return [
        {
            "verificationResult": {
                "signature": {"certificate": cert},
                "statement": {
                    "_type": "https://in-toto.io/Statement/v1",
                    "predicateType": PREDICATE,
                    "subject": [{"name": "manifest", "digest": {"sha256": r.manifest_digest[7:]}}],
                    "predicate": {"untrusted_claim": "does not authorize recovery"},
                },
            }
        }
    ]


def setup(tmp_path, p=None):
    (tmp_path / "bundle").write_bytes(b'{"signed_fixture":"test-double"}')
    (tmp_path / "root").write_bytes(ROOT)
    return GitHubRecoveryProvenance(
        p or policy(), bundle=tmp_path / "bundle", trusted_root=tmp_path / "root", executable="/usr/bin/true"
    )


def test_pinned_verifier_command_is_credential_free_and_temp_files_are_removed(tmp_path, monkeypatch):
    verifier = setup(tmp_path)
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GH_TOKEN", "GITHUB_TOKEN", "OPENAI_API_KEY"):
        monkeypatch.setenv(name, "must-not-be-inherited")
    folders = []

    def run(command, **kw):
        folders.append(Path(kw["cwd"]))
        assert not set(kw["env"]) & {
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "OPENAI_API_KEY",
        }
        assert kw["env"]["HOME"] == kw["cwd"] == kw["env"]["GH_CONFIG_DIR"]
        assert command[:3] == ["/usr/bin/true", "attestation", "verify"]
        assert "--deny-self-hosted-runners" in command
        for flag, value in {
            "--repo": policy().repository,
            "--source-digest": registration().source_revision,
            "--signer-digest": policy().signer_digest,
            "--source-ref": policy().source_ref,
            "--cert-oidc-issuer": ISSUER,
            "--predicate-type": PREDICATE,
        }.items():
            assert command[command.index(flag) + 1] == value
        assert Path(command[3]).read_bytes() == MANIFEST.encode()
        return SimpleNamespace(returncode=0, stdout=json.dumps(verified()).encode())

    with patch("adapters.github.recovery_provenance.subprocess.run", side_effect=run):
        result = verifier.verify(registration(), MANIFEST.encode(), guard=lambda: None)
    assert result == expected_provenance(registration(), policy())
    assert result["signed_source_revision_verified"] is True
    assert result["source_snapshot_digest_verified"] is False and result["recovery_authorized"] is False
    assert folders and not folders[0].exists()


@pytest.mark.parametrize(
    "field",
    [
        "issuer",
        "subjectAlternativeName",
        "buildSignerURI",
        "buildSignerDigest",
        "runnerEnvironment",
        "sourceRepositoryURI",
        "sourceRepositoryDigest",
        "sourceRepositoryRef",
        "sourceRepositoryIdentifier",
        "sourceRepositoryOwnerURI",
        "sourceRepositoryOwnerIdentifier",
        "runInvocationURI",
    ],
)
def test_even_verified_outputs_require_exact_certificate_identity(tmp_path, field):
    verifier, value = setup(tmp_path), verified()
    value[0]["verificationResult"]["signature"]["certificate"][field] = "foreign"
    with (
        patch(
            "adapters.github.recovery_provenance.subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout=json.dumps(value).encode()),
        ),
        pytest.raises(OSError),
    ):
        verifier.verify(registration(), MANIFEST.encode(), guard=lambda: None)


@pytest.mark.parametrize(
    "change", ["signature", "missing", "unsigned", "wrong-subject", "predicate", "duplicate", "many"]
)
def test_failed_signatures_or_ambiguous_results_never_become_verified(tmp_path, change):
    verifier, value, code = setup(tmp_path), verified(), 0
    if change == "signature":
        code = 1
    elif change == "missing":
        value = []
    elif change == "unsigned":
        value[0]["verificationResult"]["signature"] = {}
    elif change == "wrong-subject":
        value[0]["verificationResult"]["statement"]["subject"][0]["digest"] = {"sha256": "0" * 64}
    elif change == "predicate":
        value[0]["verificationResult"]["statement"]["predicateType"] = "untrusted"
    elif change == "many":
        value *= 31
    data = json.dumps(value).encode()
    if change == "duplicate":
        data = data.replace(b'"issuer":', b'"issuer":"duplicate","issuer":')
    with (
        patch(
            "adapters.github.recovery_provenance.subprocess.run",
            return_value=SimpleNamespace(returncode=code, stdout=data),
        ),
        pytest.raises(OSError),
    ):
        verifier.verify(registration(), MANIFEST.encode(), guard=lambda: None)


def test_tampered_manifest_or_trust_root_is_rejected_before_verifier(tmp_path):
    verifier = setup(tmp_path)
    with patch("adapters.github.recovery_provenance.subprocess.run") as run, pytest.raises(ValueError):
        verifier.verify(registration(), MANIFEST.encode() + b" ", guard=lambda: None)
    run.assert_not_called()
    (tmp_path / "root").write_bytes(b"changed-root")
    with pytest.raises(ValueError):
        GitHubRecoveryProvenance(
            policy(), bundle=tmp_path / "bundle", trusted_root=tmp_path / "root", executable="/usr/bin/true"
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("repository_id", 123),
        ("owner_id", "*"),
        ("signer_digest", "main"),
        ("signer_workflow", "sangmu1126/sky-platform/.github/workflows/attest.yml"),
        ("source_ref", "refs/heads/../main"),
        ("trusted_root_digest", "unknown"),
    ],
)
def test_invalid_or_self_signed_builder_policy_is_not_admitted(field, value):
    with pytest.raises(ValueError):
        policy(**{field: value})


def test_application_requires_exact_provenance_receipt_and_preserves_hold(operating_review_setup):
    records, actor, service, args, _ = app(operating_review_setup)
    p = policy()
    before = deepcopy(records.job)
    adapter, _, _ = native(service.registration)
    adapter.provenance = Mock(verify=Mock(return_value=expected_provenance(service.registration, p)))
    service.inspector, service.provenance_policy = adapter, p
    result = service.inspect(actor, service.registration.job_id, **args)
    assert result["provenance"]["signed_source_revision_verified"]
    assert not result["source_provenance_verified"] and not result["recovery_authorized"]
    assert records.job == before
    adapter.provenance.verify.return_value["source_snapshot_digest_verified"] = True
    with pytest.raises(OSError):
        service.inspect(actor, service.registration.job_id, **args)
    assert records.job == before


def test_missing_configured_provenance_cannot_fall_back_to_unsigned_image(operating_review_setup):
    _, actor, service, args, _ = app(operating_review_setup)
    service.provenance_policy = policy()
    with pytest.raises(OSError):
        service.inspect(actor, service.registration.job_id, **args)


def test_optional_provenance_config_is_operator_only_and_config_check_has_no_execution(
    configured_cli, tmp_path, capsys
):
    p = policy()
    setup(tmp_path)
    config = tmp_path / "policy.json"
    value = {"version": 1, **asdict(p), "bundle": "bundle", "trusted_root": "root"}
    config.write_text(json.dumps(value))
    loaded, paths = load_recovery_provenance_registration(config)
    assert loaded == p and paths["bundle"] == tmp_path / "bundle"
    image = tmp_path / "image.json"
    image.write_text(json.dumps({"version": 1, **asdict(registration())}))
    args = arguments("inspect-recovery-image") + [
        "--incident-id",
        "INC-1",
        "--expected-boundary",
        "b" * 32,
        "--expected-revision",
        "1",
        "--recovery-image-config",
        str(image),
        "--recovery-provenance-config",
        str(config),
        "--check-config",
    ]
    with (
        patch("adapters.github.recovery_provenance.shutil.which", return_value="/usr/bin/true"),
        patch("adapters.github.recovery_provenance.subprocess.run", side_effect=AssertionError("execute")),
        patch("interfaces.security_hold.RotatingDatabaseConnection", side_effect=AssertionError("db")),
        patch("boto3.Session", side_effect=AssertionError("aws")),
    ):
        main(args)
    assert "no AWS/DB calls" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        main(arguments("status") + ["--recovery-provenance-config", str(config), "--check-config"])
    config.write_text(json.dumps(value | {"source_ref": "refs/heads/*"}))
    with pytest.raises(ValueError):
        load_recovery_provenance_registration(config)
