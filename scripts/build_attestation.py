"""Prepare minimal attestation subjects without executing sources or granting access.

A signed record binds the checked ZIP/request/manifest hashes. It is not proof
that an untrusted build runner faithfully compiled that ZIP or that code is safe.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path

from application.source_artifacts import SourceArtifactService
from domain.access import LoginSource, Principal, Role
from ports.image_manifests import verify_image_manifest
from ports.remote_builds import canonical, digest, identity, validate_request, validate_result


def read(path, limit):
    with Path(path).open("rb") as stream:
        data = stream.read(limit + 1)
    if not data or len(data) > limit:
        raise ValueError("Attestation input exceeds bound")
    return data


def document(path, limit=65536):
    data = read(path, limit)
    value = json.loads(data)
    if data != canonical(value):
        raise ValueError("Exact canonical attestation input required")
    return value


def export_published(directory, request, result, manifest, build_receipt):
    """Called only after publish checks; no signing or source execution here."""
    validate_request(request)
    validate_result(result, request, result["run_id"])
    if (
        not isinstance(build_receipt, dict)
        or set(build_receipt) != {"version", "request_digest", "image_id", "archive_digest"}
        or type(build_receipt["version"]) is not int
        or build_receipt["version"] != 1
        or build_receipt["request_digest"] != digest(request)
    ):
        raise ValueError("Exact checked build receipt required")
    import re

    if not isinstance(build_receipt["archive_digest"], str) or not re.fullmatch(
        r"[a-f0-9]{64}", build_receipt["archive_digest"]
    ):
        raise ValueError("Checked archive digest required")
    if isinstance(manifest, str):
        manifest = manifest.encode()
    verify_image_manifest(manifest, result["image_digest"], build_receipt["image_id"])
    directory.mkdir(parents=True, exist_ok=False)
    (directory / "result.json").write_bytes(canonical(result))
    (directory / "build.json").write_bytes(canonical(build_receipt))
    (directory / "manifest.json").write_bytes(manifest)


def prepare(input_directory, published_directory, output_directory, *, environment=None):
    env = os.environ if environment is None else environment
    request = document(input_directory / "request.json")
    artifact, _ = validate_request(request)
    if (
        digest(request) != env["REQUEST_DIGEST"]
        or request["build_id"] != identity(env["BUILD_ID"])
        or (request["repository"], request["workflow_sha"], request["platform_code_sha"])
        != (env["GITHUB_REPOSITORY"], env["GITHUB_SHA"], env["SKY_PLATFORM_CODE_SHA"])
    ):
        raise ValueError("Signing request differs from admitted caller/code identity")
    run = env["GITHUB_RUN_ID"]
    if not run.isascii() or not run.isdigit() or not 1 <= len(run) <= 20 or run.startswith("0"):
        raise ValueError("Exact signing workflow run required")
    result = document(published_directory / "result.json")
    validate_result(result, request, int(run))
    receipt = document(published_directory / "build.json", 4096)
    # Reuse the publisher's exact receipt schema without loading/running its tar.
    if set(receipt) != {"version", "request_digest", "image_id", "archive_digest"} or (
        type(receipt["version"]) is not int
        or receipt["version"] != 1
        or receipt["request_digest"] != digest(request)
    ):
        raise ValueError("Published receipt differs from signing request")
    import re

    if not isinstance(receipt["archive_digest"], str) or not re.fullmatch(
        r"[a-f0-9]{64}", receipt["archive_digest"]
    ):
        raise ValueError("Archive identity required")
    manifest = read(published_directory / "manifest.json", 4 * 1024 * 1024)
    verify_image_manifest(manifest, result["image_digest"], receipt["image_id"])
    payload = read(input_directory / "source.zip", artifact.size)

    class Objects:
        def get(self, selected):
            if selected != artifact:
                raise ValueError("Unexpected signing source")
            return payload

    principal = Principal(
        request["created_by"], artifact.organization_id, Role.DEPLOYER, LoginSource.CORPORATE_SSO
    )
    # Uses existing bounded extraction and independently checks ZIP bytes and
    # the normalized source tree hash. No source code, package manager or Docker.
    with SourceArtifactService(Objects()).restore(principal, artifact):
        pass
    statement = {
        "protocol": "sky-build-input-binding-v1",
        "build_id": request["build_id"],
        "request_digest": digest(request),
        "source_zip_sha256": artifact.sha256,
        "source_zip_size": artifact.size,
        "source_digest": request["source_digest"],
        "plan_digest": request["plan_digest"],
        "image_digest": result["image_digest"],
        "config_digest": receipt["image_id"],
        "archive_digest": receipt["archive_digest"],
        "repository": request["repository"],
        "workflow_sha": request["workflow_sha"],
        "platform_code_sha": request["platform_code_sha"],
        "run_id": int(run),
        "zip_and_source_digest_checked": True,
        "faithful_compilation_verified": False,
        "image_safety_verified": False,
        "recovery_authorized": False,
    }
    output_directory.mkdir(parents=True, exist_ok=False)
    (output_directory / "manifest.json").write_bytes(manifest)
    (output_directory / "statement.json").write_bytes(canonical(statement))
    return {
        "manifest_digest": result["image_digest"],
        "statement_digest": "sha256:" + hashlib.sha256(canonical(statement)).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=Path("build-input"))
    parser.add_argument("--published", type=Path, default=Path("published-proof"))
    parser.add_argument("--output", type=Path, default=Path("signing-output"))
    args = parser.parse_args()
    try:
        prepare(args.input, args.published, args.output)
    except (OSError, ValueError, TypeError, KeyError):
        parser.exit(1, "Build attestation inputs rejected; no source execution or recovery authorization.\n")


if __name__ == "__main__":
    main()
