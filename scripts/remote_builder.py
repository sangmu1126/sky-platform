"""Trusted sky-builder runner; user code runs in the credential-free build job.

Transfer the entire output directory (image.tar AND build.json) to publish.
Legacy image-only artifacts fail closed and require a fresh build. The receipt
checks request/archive/image consistency; it is not a signature and depends on
the trusted workflow and artifact transport for authenticity.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import fields
from pathlib import Path

from adapters.aws.build_objects import S3BuildObjects
from adapters.aws.source_artifacts import S3ArtifactSettings, S3SourceArtifactStore
from adapters.build.image import ImageBuilder
from application.deployment_core import DeploymentPlan
from application.source_artifacts import SourceArtifactService
from domain.access import LoginSource, Principal, Role
from ports.image_manifests import MANIFEST_TYPES, verify_image_manifest
from ports.remote_builds import canonical, digest, identity, request_key, validate_request, validate_result


def command(args, timeout=1200, *, env=None):
    # Capture bounded diagnostics on disk; never print user build output or credentials.
    with tempfile.TemporaryFile(mode="w+") as output:
        result = subprocess.run(
            args, check=False, stdout=output, stderr=subprocess.STDOUT, text=True, timeout=timeout, env=env
        )
        output.seek(0)
        text = output.read(65536)
    if (
        result.returncode
        and args[:3] == ["docker", "image", "inspect"]
        and "--platform" in args
        and "unknown flag: --platform" in text
    ):
        # Old CLI: still check the built single-platform image's actual OS/architecture.
        selected = args.index("--platform")
        return command(args[:selected] + args[selected + 2 :], timeout, env=env)
    if result.returncode:
        raise OSError("Builder command failed")
    return text


@contextmanager
def isolated_docker_config():
    """Keep CLI auth out of caller config; remove files even when logout fails.

    Normal context exit is covered. Abrupt process/host termination still relies
    on the ephemeral runner lifecycle; this does not revoke the registry token.
    """
    with tempfile.TemporaryDirectory(prefix="sky-publish-auth-") as directory:
        environment = dict(os.environ, DOCKER_CONFIG=directory)
        yield environment


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
    (directory / "source.zip").write_bytes(S3SourceArtifactStore(settings).get(artifact))


def build(directory, output):
    request, artifact, raw_plan = inputs(directory)
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
    from botocore.exceptions import ClientError

    request, _, _ = inputs(directory)
    image_id = verified_build(request, output)
    from adapters.build.saved_archive import validate_saved_archive

    archive_identity = validate_saved_archive(output / "image.tar", image_id, "sky-build:" + request["build_id"])
    settings = S3ArtifactSettings(
        os.environ["SKY_ARTIFACTS_BUCKET"], os.environ["AWS_REGION"], os.environ["SKY_AWS_ACCOUNT_ID"]
    )
    if (request["bucket"], request["account_id"], request["region"]) != (
        settings.bucket,
        settings.account_id,
        settings.region,
    ):
        raise ValueError("Publish AWS scope mismatch")
    if boto3.client("sts").get_caller_identity()["Account"] != settings.account_id:
        raise ValueError("Unexpected publish account")
    ecr = boto3.client("ecr", region_name=settings.region)
    objects = S3BuildObjects(settings)
    result_key = f"builds/{request['build_id']}/result.json"
    # app-builder may write builds/ but only read sources/. Existing image tags
    # therefore require reconciliation rather than reading/replacing a prior result.
    registry = f"{settings.account_id}.dkr.ecr.{settings.region}.amazonaws.com"
    auth = ecr.get_authorization_token(registryIds=[settings.account_id])["authorizationData"][0]
    username, password = base64.b64decode(auth["authorizationToken"]).decode().split(":", 1)
    with isolated_docker_config() as docker_environment:

        def docker_command(args, timeout=1200):
            return command(args, timeout=timeout, env=docker_environment)

        try:
            login = subprocess.run(
                ["docker", "login", "--username", username, "--password-stdin", registry],
                check=False,
                input=password,
                capture_output=True,
                text=True,
                timeout=30,
                env=docker_environment,
            )
            if login.returncode:
                raise OSError("Builder registry login failed")
            tag = "build-" + request["build_id"]
            try:
                found = ecr.describe_images(
                    registryId=settings.account_id, repositoryName="sky-managed", imageIds=[{"imageTag": tag}]
                )
            except ClientError as error:
                if error.response.get("Error", {}).get("Code") != "ImageNotFoundException":
                    raise
                found = None
            if found is not None:
                # Crash after push: never overwrite an existing tag with a potentially different rebuild.
                raise ValueError("Existing image without result requires explicit reconciliation")
            local = "sky-build:" + request["build_id"]
            docker_command(["docker", "load", "-i", str(output / "image.tar")])
            loaded_id = docker_command(["docker", "image", "inspect", "--format", "{{.Id}}", local]).strip()
            if loaded_id not in archive_identity["image_identities"]:
                raise ValueError("Loaded image identity mismatch")
            if (
                docker_command(
                    ["docker", "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", local]
                ).strip()
                != "linux/amd64"
            ):
                raise ValueError("Unexpected image architecture")
            destination = registry + "/sky-managed:" + tag
            docker_command(["docker", "tag", local, destination])
            docker_command(["docker", "push", "--platform", "linux/amd64", destination], timeout=300)
            image_digest = ecr.describe_images(
                registryId=settings.account_id, repositoryName="sky-managed", imageIds=[{"imageTag": tag}]
            )["imageDetails"][0]["imageDigest"]
            published = ecr.batch_get_image(
                registryId=settings.account_id,
                repositoryName="sky-managed",
                imageIds=[{"imageDigest": image_digest}],
                acceptedMediaTypes=list(MANIFEST_TYPES),
            )
            images = published.get("images", [])
            if (
                published.get("failures")
                or len(images) != 1
                or images[0].get("imageId", {}).get("imageDigest") != image_digest
            ):
                raise ValueError("Published registry image unavailable or ambiguous")
            verify_image_manifest(images[0].get("imageManifest"), image_digest, image_id)
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
                "image_digest": image_digest,
                "image": registry + "/sky-managed@" + image_digest,
            }
            validate_result(result, request, result["run_id"])
            objects.put(result_key, result)
            if attestation_output is not None:
                from scripts.build_attestation import document, export_published

                export_published(
                    attestation_output,
                    request,
                    result,
                    images[0]["imageManifest"],
                    document(output / "build.json", 4096),
                )
        finally:
            # Always attempt registry credential cleanup, including partial login failures.
            # Preserve the original failure if cleanup also fails; a cleanup-only
            # failure still fails the job rather than reporting complete success.
            failed = sys.exc_info()[0] is not None
            try:
                docker_command(["docker", "logout", registry], timeout=30)
            except (OSError, subprocess.TimeoutExpired):
                if not failed:
                    raise


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
