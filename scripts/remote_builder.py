"""Trusted sky-builder runner; user code runs in the credential-free build job.

Transfer the entire output directory (image.tar AND build.json) to publish.
Legacy image-only artifacts fail closed and require a fresh build. The receipt
checks request/archive/image consistency; it is not a signature and depends on
the trusted workflow and artifact transport for authenticity.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import fields
from pathlib import Path

from adapters.aws.build_objects import S3BuildObjects
from adapters.aws.source_artifacts import S3ArtifactSettings, S3SourceArtifactStore
from adapters.build.image import ImageBuilder
from application.deployment_core import DeploymentPlan
from application.source_artifacts import SourceArtifactService
from domain.access import LoginSource, Principal, Role
from ports.remote_builds import canonical, digest, identity, request_key, validate_request, validate_result


def command(args, timeout=1200, *, env=None):
    from adapters.build.process import bounded_command

    # No unbounded temporary log file: a noisy RUN cannot fill the runner disk.
    returncode, text = bounded_command(args, timeout=timeout, env=env)
    if (
        returncode
        and args[:3] == ["docker", "image", "inspect"]
        and "--platform" in args
        and "unknown flag: --platform" in text
    ):
        # Old CLI: still check the built single-platform image's actual OS/architecture.
        selected = args.index("--platform")
        return command(args[:selected] + args[selected + 2 :], timeout, env=env)
    if returncode:
        raise OSError("Builder command failed")
    return text


def inputs(directory):
    request = json.loads((directory / "request.json").read_bytes())
    artifact, plan = validate_request(request)
    if digest(request) != os.environ["REQUEST_DIGEST"] or request["build_id"] != identity(
        os.environ["BUILD_ID"]
    ):
        raise ValueError("Builder request digest/identity mismatch")
    if (request["repository"], request["workflow_sha"], request["platform_code_sha"]) != (
        os.environ["GITHUB_REPOSITORY"],
        os.environ["GITHUB_SHA"],
        os.environ["SKY_PLATFORM_CODE_SHA"],
    ):
        raise ValueError("Builder workflow/code provenance mismatch")
    return request, artifact, plan


def prepare(directory):
    # Scope and request-key restrictions precede S3 object reads.
    identity(os.environ["BUILD_ID"])
    settings = S3ArtifactSettings(
        os.environ["SKY_ARTIFACTS_BUCKET"], os.environ["AWS_REGION"], os.environ["SKY_AWS_ACCOUNT_ID"]
    )
    key = os.environ["REQUEST_KEY"]
    import re

    if not re.fullmatch(
        r"sources/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[0-9a-f]{32}/build-requests/[0-9a-f-]{36}\.json", key
    ):
        raise ValueError("Invalid immutable build request key")
    request = S3BuildObjects(settings).read(key)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "request.json").write_bytes(canonical(request))
    request, artifact, _ = inputs(directory)
    if (request["bucket"], request["account_id"], request["region"]) != (
        settings.bucket,
        settings.account_id,
        settings.region,
    ) or request_key(request) != key:
        raise ValueError("Builder AWS/source scope mismatch")
    from adapters.aws.build_execution_grant import execution_guard

    execution_guard(request, settings, lambda: None)()
    (directory / "source.zip").write_bytes(S3SourceArtifactStore(settings).get(artifact))


def build(directory, output):
    request, artifact, raw_plan = inputs(directory)
    profile = os.environ.get("SKY_BUILD_SANDBOX_PROFILE_JSON")
    if profile is not None:
        from scripts.vm_build_controller import build_in_vm

        return build_in_vm(directory, output, request, artifact, raw_plan, profile)
    if os.environ.get("SKY_REQUIRE_ISOLATED_BUILDS") == "true":
        raise ValueError(
            "Hosted builds require a sealed disposable VM registration; no local Docker fallback"
        )
    # This phase must run in a separate VM/job with no cloud credentials or OIDC permission.
    if any(
        os.environ.get(name)
        for name in (
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            "AWS_PROFILE",
            "AWS_DEFAULT_PROFILE",
            "AWS_SHARED_CREDENTIALS_FILE",
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            "OPENAI_API_KEY",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "GOOGLE_CREDENTIALS",
            "AZURE_CLIENT_SECRET",
            "ACTIONS_RUNTIME_TOKEN",
        )
    ):
        raise ValueError("Build job must not carry AWS/OIDC credentials or other provider credentials")
    payload = (directory / "source.zip").read_bytes()

    class Objects:
        def get(self, selected):
            if selected != artifact:
                raise ValueError("Unexpected build source")
            return payload

    principal = Principal(
        request["created_by"], artifact.organization_id, Role.DEPLOYER, LoginSource.CORPORATE_SSO
    )
    plan = DeploymentPlan(
        **{
            key: value
            for key, value in raw_plan.items()
            if key in {field.name for field in fields(DeploymentPlan)}
        }
    )
    image = "sky-build:" + request["build_id"]
    offline = os.environ.get("SKY_OFFLINE_BUILD_BASES_JSON")
    if os.environ.get("SKY_REQUIRE_ISOLATED_BUILDS") == "true" and not offline:
        raise ValueError("Hosted builds require an explicitly registered isolated build profile")
    offline_options = {} if offline is None else {"offline_bases": json.loads(offline)}
    with SourceArtifactService(Objects()).restore(principal, artifact) as project:
        ca = None
        if raw_plan.get("database_profile") == "shared-postgres-v1":
            profile = raw_plan.get("infrastructure_profile", {})
            if profile.get("requirements") != ["database"] or profile.get("database_engines") != [
                "postgresql"
            ]:
                raise ValueError("Only a prepared PostgreSQL source may request the shared DB build profile")
            ca = Path(__file__).resolve().parents[1] / "src/assets/infra/rds-global-bundle.pem"
        elif raw_plan.get("database_profile") is not None:
            raise ValueError("Unsupported remote build database profile")
        ImageBuilder(command, lambda *_: None).build(
            project, plan, image, platform="linux/amd64", extra_ca_bundle=ca, **offline_options
        )
    output.mkdir(parents=True, exist_ok=True)
    command(["docker", "save", "-o", str(output / "image.tar"), image])
    from adapters.build.saved_archive import validate_saved_archive

    image_id = validate_saved_archive(output / "image.tar", None, image)["config_digest"]
    (output / "build.json").write_bytes(
        canonical(
            {
                "version": 1,
                "request_digest": digest(request),
                "image_id": image_id,
                "archive_digest": archive_digest(output / "image.tar"),
            }
        )
    )


def archive_digest(path):
    with path.open("rb") as archive:
        return hashlib.file_digest(archive, "sha256").hexdigest()


def verified_build(request, output):
    """Check transport integrity, not a signature against a malicious builder."""
    path = output / "build.json"
    with path.open("rb") as source:
        raw = source.read(4097)
    if len(raw) > 4096:
        raise ValueError("Oversized build receipt")
    receipt = json.loads(raw)
    if (
        raw != canonical(receipt)
        or not isinstance(receipt, dict)
        or set(receipt) != {"version", "request_digest", "image_id", "archive_digest"}
        or type(receipt["version"]) is not int
        or receipt["version"] != 1
        or receipt["request_digest"] != digest(request)
        or not isinstance(receipt["image_id"], str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", receipt["image_id"])
        or receipt["archive_digest"] != archive_digest(output / "image.tar")
    ):
        raise ValueError("Build artifact identity mismatch")
    return receipt["image_id"]


def publish(directory, output, *, attestation_output=None):
    import boto3

    from adapters.aws.data_image_publisher import EcrDataPublisher

    request, _, _ = inputs(directory)
    image_id = verified_build(request, output)
    settings = S3ArtifactSettings(
        os.environ["SKY_ARTIFACTS_BUCKET"], os.environ["AWS_REGION"], os.environ["SKY_AWS_ACCOUNT_ID"]
    )

    def scope_guard():
        # A workflow-pinned request cannot grant access outside operator settings.
        if (request["bucket"], request["account_id"], request["region"]) != (
            settings.bucket,
            settings.account_id,
            settings.region,
        ):
            raise ValueError("Publish AWS scope mismatch")

    from adapters.aws.build_execution_grant import execution_guard

    guard = execution_guard(request, settings, scope_guard)
    required = os.environ.get("SKY_REQUIRE_SIGNED_BUILDS", "false")
    if required not in {"true", "false"}:
        raise ValueError("Explicit build signature requirement required")
    identity = None
    if required == "true":
        from adapters.aws.build_trust import load_build_trust
        from scripts.build_attestation import verify_source_input

        identity = load_build_trust(
            os.environ.get("SKY_BUILD_SIGNING_TRUST_JSON"),
            account_id=settings.account_id,
            region=settings.region,
        )
        verify_source_input(directory, request)
    security = None
    if os.environ.get("GITHUB_ACTIONS") == "true" or os.environ.get("SKY_REQUIRE_IMAGE_INSPECTION") == "true":
        from adapters.build.image_security import publication_security

        security = publication_security(output, archive_digest(output / "image.tar"))
        if identity is None:
            raise ValueError("Inspected hosted images require signed security receipts")
    scope_guard()
    published = EcrDataPublisher(
        account_id=settings.account_id,
        region=settings.region,
        repository="sky-managed",
        session=boto3,
        guard=guard,
    ).publish(
        output / "image.tar",
        image_id=image_id,
        local_tag="sky-build:" + request["build_id"],
        tag="build-" + request["build_id"],
    )
    result = {
        "version": 1,
        "build_id": request["build_id"],
        "request_digest": digest(request),
        "source_digest": request["source_digest"],
        "plan_digest": request["plan_digest"],
        "platform": "linux/amd64",
        "repository": request["repository"],
        "workflow_sha": request["workflow_sha"],
        "platform_code_sha": request["platform_code_sha"],
        "run_id": int(os.environ["GITHUB_RUN_ID"]),
        "image_digest": published["image_digest"],
        "image": published["image"],
    }
    validate_result(result, request, result["run_id"])
    guard()
    objects = S3BuildObjects(settings)
    if identity is not None:
        import tempfile

        from adapters.aws.kms_build_signature import AwsKmsBuildSigner
        from scripts.build_attestation import document, export_published, prepare

        with tempfile.TemporaryDirectory(prefix="sky-sign-checked-data-") as temporary:
            root = Path(temporary)
            export_published(
                root / "published",
                request,
                result,
                published["manifest"],
                document(output / "build.json", 4096),
            )
            prepare(directory, root / "published", root / "prepared")
            statement = document(root / "prepared" / "statement.json")
            if security is not None:
                statement["security"] = security
            bundle = AwsKmsBuildSigner(identity).sign(
                statement,
                request,
                image_digest=result["image_digest"],
                config_digest=image_id,
                run_id=result["run_id"],
                guard=guard,
            )
            objects.put(f"builds/{request['build_id']}/signature.json", bundle)
    objects.put(f"builds/{request['build_id']}/result.json", result)
    if attestation_output is not None:
        from scripts.build_attestation import document, export_published

        export_published(
            attestation_output, request, result, published["manifest"], document(output / "build.json", 4096)
        )


def main():
    from botocore.exceptions import BotoCoreError, ClientError

    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("prepare", "build", "publish"))
    parser.add_argument("--input", type=Path, default=Path("build-input"))
    parser.add_argument("--output", type=Path, default=Path("build-output"))
    parser.add_argument("--attestation-output", type=Path)
    args = parser.parse_args()
    if args.attestation_output is not None and args.mode != "publish":
        parser.error("Attestation export requires publish")
    try:
        if args.mode == "prepare":
            prepare(args.input)
        elif args.mode == "build":
            build(args.input, args.output)
        else:
            publish(args.input, args.output, attestation_output=args.attestation_output)
    except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired, BotoCoreError, ClientError):
        sys.exit("Remote builder failed; inspect scope, inputs and immutable build state.")


if __name__ == "__main__":
    main()
