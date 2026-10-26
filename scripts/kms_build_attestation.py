"""Trusted operator/isolated signer CLI. Private repositories need no GitHub attestation API.

The expected request must be independently selected by trusted composition, not
extracted from a signature. This CLI does not verify live approval DB state.
"""

import argparse
import base64
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from adapters.aws.kms_build_signature import AwsKmsBuildSigner
from application.kms_build_signature import KmsBuildSigningIdentity, verify_build_signature
from ports.remote_builds import canonical, validate_request
from scripts.build_attestation import document, prepare


def load_identity(path):
    value = document(path, 4096)
    if (
        not isinstance(value, dict)
        or set(value) != {"version", "key_arn", "public_key_der"}
        or (
            type(value["version"]) is not int
            or value["version"] != 1
            or not isinstance(value["public_key_der"], str)
        )
    ):
        raise ValueError("Exact operator KMS public trust registration required")
    raw = base64.b64decode(value["public_key_der"], validate=True)
    if base64.b64encode(raw).decode() != value["public_key_der"]:
        raise ValueError("Canonical public trust encoding required")
    return KmsBuildSigningIdentity(value["key_arn"], raw)


def sign_inputs(input_directory, published, output, identity, *, environment=None, signer=None):
    env = os.environ if environment is None else environment
    if output.exists():
        raise FileExistsError("Existing signed bundle cannot be overwritten")
    with tempfile.TemporaryDirectory(prefix="sky-kms-input-binding-") as directory:
        prepared = Path(directory) / "subjects"
        prepare(input_directory, published, prepared, environment=env)
        statement = document(prepared / "statement.json")
        request = document(input_directory / "request.json")
        signer = signer or AwsKmsBuildSigner(identity)
        bundle = signer.sign(
            statement,
            request,
            image_digest=statement["image_digest"],
            config_digest=statement["config_digest"],
            run_id=int(env["GITHUB_RUN_ID"]),
            guard=lambda: None,
        )
        verify_build_signature(
            bundle,
            identity,
            request,
            image_digest=statement["image_digest"],
            config_digest=statement["config_digest"],
            run_id=int(env["GITHUB_RUN_ID"]),
            now=datetime.now(UTC),
        )
        # Exclusive create; a crash after signing never silently replaces an older artifact.
        with output.open("xb") as stream:
            stream.write(canonical(bundle))
        return {"signed": True, "key_arn": identity.key_arn, "recovery_authorized": False}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("sign", "verify"))
    parser.add_argument("--key-config", type=Path, required=True)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--published", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--expected-request", type=Path)
    parser.add_argument("--image-digest")
    parser.add_argument("--config-digest")
    parser.add_argument("--run-id", type=int)
    args = parser.parse_args(argv)
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm

    try:
        identity = load_identity(args.key_config)
        if args.mode == "sign":
            if not all((args.input, args.published, args.output)) or any(
                (args.bundle, args.expected_request, args.image_digest, args.config_digest, args.run_id)
            ):
                raise ValueError("Signing requires only checked source/publish inputs and output")
            from botocore.exceptions import BotoCoreError, ClientError

            try:
                result = sign_inputs(args.input, args.published, args.output, identity)
            except (BotoCoreError, ClientError):
                raise OSError("KMS signing request unavailable or outcome uncertain") from None
        else:
            if not all(
                (args.bundle, args.expected_request, args.image_digest, args.config_digest, args.run_id)
            ) or any((args.input, args.published, args.output)):
                raise ValueError("Verification requires independent expected request and image/run pins")
            request = document(args.expected_request)
            validate_request(request)
            # Bundle must be canonical too; no duplicate or unknown JSON interpretation.
            bundle = document(args.bundle)
            result = verify_build_signature(
                bundle,
                identity,
                request,
                image_digest=args.image_digest,
                config_digest=args.config_digest,
                run_id=args.run_id,
                now=datetime.now(UTC),
            )
        print(json.dumps(result), flush=True)
    except (ValueError, TypeError, KeyError, OSError, ImportError, InvalidSignature, UnsupportedAlgorithm):
        parser.exit(1, "KMS build signature rejected or unavailable; no recovery authorization granted.\n")


if __name__ == "__main__":
    main()
