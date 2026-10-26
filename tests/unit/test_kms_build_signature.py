import base64
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from adapters.aws.kms_build_signature import AwsKmsBuildSigner
from application.kms_build_signature import KmsBuildSigningIdentity, verify_build_signature
from ports.remote_builds import canonical, digest
from scripts.build_attestation import prepare
from scripts.check_build_attestation import fixture
from scripts.kms_build_attestation import load_identity, main, sign_inputs

NOW = datetime.now(UTC)
ARN = "arn:aws:kms:ap-northeast-2:000000000000:key/12345678-1234-1234-1234-123456789abc"


@pytest.fixture
def context(tmp_path):
    env = {
        "GITHUB_REPOSITORY": "sangmu1126/sky-builder",
        "GITHUB_SHA": "a" * 40,
        "SKY_PLATFORM_CODE_SHA": "b" * 40,
        "GITHUB_RUN_ID": "123",
    }
    request = fixture(tmp_path, environment=env)
    env.update(BUILD_ID=request["build_id"], REQUEST_DIGEST=digest(request))
    prepare(tmp_path / "build-input", tmp_path / "published-proof", tmp_path / "prepared", environment=env)
    statement = json.loads((tmp_path / "prepared/statement.json").read_bytes())
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    identity = KmsBuildSigningIdentity(ARN, public)
    kms, sts = Mock(), Mock()
    for client in (kms, sts):
        client.meta = SimpleNamespace(region_name=identity.region)
    sts.get_caller_identity.return_value = {"Account": identity.account_id}
    kms.describe_key.return_value = {
        "KeyMetadata": {
            "Arn": ARN,
            "AWSAccountId": identity.account_id,
            "KeyUsage": "SIGN_VERIFY",
            "KeySpec": "ECC_NIST_P256",
            "KeyState": "Enabled",
            "Enabled": True,
            "MultiRegion": False,
            "Origin": "AWS_KMS",
        }
    }
    kms.get_public_key.return_value = {
        "KeyId": ARN,
        "PublicKey": public,
        "KeyUsage": "SIGN_VERIFY",
        "KeySpec": "ECC_NIST_P256",
        "SigningAlgorithms": ["ECDSA_SHA_256"],
    }

    def sign(**kwargs):
        assert kwargs["KeyId"] == ARN and kwargs["MessageType"] == "DIGEST"
        assert kwargs["SigningAlgorithm"] == "ECDSA_SHA_256" and len(kwargs["Message"]) == 32
        return {
            "KeyId": ARN,
            "SigningAlgorithm": "ECDSA_SHA_256",
            "Signature": private.sign(kwargs["Message"], ec.ECDSA(utils.Prehashed(hashes.SHA256()))),
        }

    kms.sign.side_effect = sign
    session = Mock(client=lambda name, **kw: {"kms": kms, "sts": sts}[name])
    signer = AwsKmsBuildSigner(identity, session=session, clock=lambda: NOW)
    options = {
        "image_digest": statement["image_digest"],
        "config_digest": statement["config_digest"],
        "run_id": 123,
    }
    return SimpleNamespace(
        root=tmp_path,
        env=env,
        request=request,
        statement=statement,
        private=private,
        identity=identity,
        kms=kms,
        sts=sts,
        session=session,
        signer=signer,
        options=options,
    )


def signed(c, **kwargs):
    return c.signer.sign(c.statement, c.request, **c.options, guard=lambda: None, **kwargs)


def test_native_sign_and_offline_verify_preserve_limited_claims(context):
    c = context
    bundle = signed(c)
    with patch("boto3.Session", side_effect=AssertionError("offline verification cannot call AWS")):
        result = verify_build_signature(bundle, c.identity, c.request, **c.options, now=NOW)
    assert result["signature_verified"] and result["expected_input_binding_matched"]
    assert not result["current_approval_verified"] and not result["workflow_identity_certified_by_provider"]
    assert not result["key_liveness_checked"] and not result["recovery_authorized"]
    assert not result["faithful_compilation_verified"] and not result["image_safety_verified"]
    assert set(bundle) == {"payload", "signature"} and "public_key_der" not in bundle["payload"]
    c.kms.sign.assert_called_once()
    c.kms.decrypt.assert_not_called()


@pytest.mark.parametrize(
    "change",
    ["payload", "signature", "algorithm", "key-arn", "fingerprint", "future", "expired", "too-long", "extra"],
)
def test_signature_or_trust_substitution_and_invalid_lifetimes_fail(context, change):
    c = context
    bundle, now = signed(c), NOW
    if change == "payload":
        bundle["payload"]["statement"]["source_digest"] = "f" * 64
    elif change == "signature":
        raw = bytearray(base64.b64decode(bundle["signature"]))
        raw[-1] ^= 1
        bundle["signature"] = base64.b64encode(raw).decode()
    elif change in {"algorithm", "key-arn", "fingerprint"}:
        bundle["payload"][
            {"algorithm": "algorithm", "key-arn": "key_arn", "fingerprint": "public_key_fingerprint"}[change]
        ] = "wrong"
    elif change == "future":
        now = NOW - timedelta(seconds=1)
    elif change == "expired":
        now = NOW + timedelta(seconds=900)
    elif change == "too-long":
        bundle["payload"]["expires_at"] = (NOW + timedelta(hours=2)).isoformat()
    else:
        bundle["public_key_der"] = base64.b64encode(c.identity.public_key_der).decode()
    with pytest.raises((ValueError, InvalidSignature)):
        verify_build_signature(bundle, c.identity, c.request, **c.options, now=now)


@pytest.mark.parametrize(
    "change", ["job", "source", "run", "image", "config", "build-id", "repository", "code"]
)
def test_a_valid_signature_for_another_expected_request_is_rejected(context, change):
    c = context
    bundle, request, options = signed(c), deepcopy(c.request), dict(c.options)
    if change == "job":
        request["job_id"] = "f" * 16
    elif change == "source":
        request["source_ref"]["sha256"] = "f" * 64
    elif change in {"run", "image", "config"}:
        options[{"run": "run_id", "image": "image_digest", "config": "config_digest"}[change]] = (
            456 if change == "run" else "sha256:" + "f" * 64
        )
    elif change == "build-id":
        request["build_id"] = "00000000-0000-4000-8000-000000000000"
    elif change == "repository":
        request["repository"] = "foreign/builder"
    else:
        request["platform_code_sha"] = "f" * 40
    with pytest.raises(ValueError):
        verify_build_signature(bundle, c.identity, request, **options, now=NOW)


@pytest.mark.parametrize(
    "change",
    [
        "account",
        "region",
        "disabled",
        "key-spec",
        "usage",
        "origin",
        "multi-region",
        "public-key",
        "response-key",
        "response-signature",
    ],
)
def test_wrong_native_key_metadata_or_response_fails_closed(context, change):
    c = context
    metadata = c.kms.describe_key.return_value["KeyMetadata"]
    if change == "account":
        c.sts.get_caller_identity.return_value["Account"] = "111111111111"
    elif change == "region":
        c.kms.meta.region_name = "us-east-1"
    elif change == "disabled":
        metadata["Enabled"] = False
    elif change == "key-spec":
        metadata["KeySpec"] = "RSA_2048"
    elif change == "usage":
        metadata["KeyUsage"] = "ENCRYPT_DECRYPT"
    elif change == "origin":
        metadata["Origin"] = "EXTERNAL"
    elif change == "multi-region":
        metadata["MultiRegion"] = True
    elif change == "public-key":
        c.kms.get_public_key.return_value["PublicKey"] = b"wrong"
    else:
        original = c.kms.sign.side_effect
        c.kms.sign.side_effect = lambda **kwargs: (
            original(**kwargs)
            | {
                "KeyId" if change == "response-key" else "Signature": "wrong"
                if change == "response-key"
                else b"wrong"
            }
        )
    with pytest.raises((ValueError, InvalidSignature)):
        signed(c)
    if not change.startswith("response-"):
        c.kms.sign.assert_not_called()


def test_explicit_key_registration_never_uses_bundle_supplied_trust(context):
    c = context
    path = c.root / "trust.json"
    path.write_bytes(
        canonical(
            {
                "version": 1,
                "key_arn": ARN,
                "public_key_der": base64.b64encode(c.identity.public_key_der).decode(),
            }
        )
    )
    assert load_identity(path) == c.identity
    with pytest.raises(ValueError):
        KmsBuildSigningIdentity(ARN.replace("key/", "alias/"), c.identity.public_key_der)


def test_private_cli_signs_checked_inputs_and_refuses_output_overwrite(context):
    c = context
    output = c.root / "bundle.json"
    result = sign_inputs(
        c.root / "build-input",
        c.root / "published-proof",
        output,
        c.identity,
        environment=c.env,
        signer=c.signer,
    )
    assert result["signed"] and result["recovery_authorized"] is False
    with pytest.raises(FileExistsError):
        sign_inputs(
            c.root / "build-input",
            c.root / "published-proof",
            output,
            c.identity,
            environment=c.env,
            signer=c.signer,
        )
    c.kms.sign.assert_called_once()
    bundle = json.loads(output.read_bytes())
    assert verify_build_signature(bundle, c.identity, c.request, **c.options, now=NOW)["signature_verified"]


def test_verification_cli_needs_independent_expected_request_and_makes_no_cloud_calls(context, capsys):
    c = context
    path = c.root / "trust.json"
    path.write_bytes(
        canonical(
            {
                "version": 1,
                "key_arn": ARN,
                "public_key_der": base64.b64encode(c.identity.public_key_der).decode(),
            }
        )
    )
    bundle = c.root / "bundle.json"
    bundle.write_bytes(canonical(signed(c)))
    with patch("boto3.Session", side_effect=AssertionError("offline")):
        main(
            [
                "verify",
                "--key-config",
                str(path),
                "--bundle",
                str(bundle),
                "--expected-request",
                str(c.root / "build-input/request.json"),
                "--image-digest",
                c.options["image_digest"],
                "--config-digest",
                c.options["config_digest"],
                "--run-id",
                "123",
            ]
        )
    result = json.loads(capsys.readouterr().out)
    assert result["expected_input_binding_matched"] and not result["current_approval_verified"]


def test_guard_revocation_after_kms_sign_never_returns_a_bundle(context):
    c = context

    def guard():
        if c.kms.sign.called:
            raise PermissionError("current operation ownership revoked")

    with pytest.raises(PermissionError):
        c.signer.sign(c.statement, c.request, **c.options, guard=guard)
    c.kms.sign.assert_called_once()


def test_private_signing_cli_rejects_replaced_zip_before_any_kms_sign(context):
    c = context
    with (c.root / "build-input/source.zip").open("ab") as stream:
        stream.write(b"replaced input")
    output = c.root / "bundle.json"
    with pytest.raises(ValueError):
        sign_inputs(
            c.root / "build-input",
            c.root / "published-proof",
            output,
            c.identity,
            environment=c.env,
            signer=c.signer,
        )
    c.kms.sign.assert_not_called()
    assert not output.exists()
