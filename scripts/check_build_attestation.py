"""Synthetic bytes only: exercise signing input checks, never build or call AWS."""

import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from application.deployment_core import source_digest
from application.source_artifacts import SourceArtifactService
from domain.access import LoginSource, Principal, Role
from ports.artifacts import SourceArtifact
from ports.remote_builds import BuildSettings, canonical, digest, request_for
from scripts.build_attestation import export_published


def fixture(directory, *, environment=None):
    env = os.environ if environment is None else environment
    project = directory / "project"
    project.mkdir(parents=True)
    (project / "index.html").write_text("Synthetic signing fixture; no app build or deployment.\n")
    objects = {}
    store = SimpleNamespace(put=lambda ref, data: objects.update({ref: data}))
    principal = Principal("fixture", "fixture", Role.DEPLOYER, LoginSource.CORPORATE_SSO)
    original = SourceArtifact("fixture", "signing", "a" * 32, "original", "b" * 64, 1, "c" * 64)
    source = SourceArtifactService(store).capture_prepared(
        principal, original, project, expected_digest=source_digest(project)
    )
    plan = {
        "target": "aws",
        "replicas": 1,
        "source_digest": source.source_digest,
        "dockerfile_source": "generated",
        "dockerfile": "FROM scratch\n",
    }
    settings = BuildSettings(
        env["GITHUB_REPOSITORY"],
        "main",
        env["GITHUB_SHA"],
        env["SKY_PLATFORM_CODE_SHA"],
        "synthetic-no-aws-access",
        "000000000000",
        "ap-northeast-2",
    )
    command = {
        "version": 1,
        "target": "aws",
        "account_id": settings.account_id,
        "region": settings.region,
        "organization_id": source.organization_id,
        "created_by": "fixture",
        "job_id": "a" * 16,
        "approval_id": str(uuid4()),
        "source_ref": source.record(),
        "source_digest": source.source_digest,
        "approved_plan_json": canonical(plan).decode(),
        "plan_digest": digest(plan),
    }
    request = request_for(
        SimpleNamespace(kind="deploy", command=command, id=str(uuid4())), "fixture", settings
    )
    inputs = directory / "build-input"
    inputs.mkdir()
    (inputs / "request.json").write_bytes(canonical(request))
    (inputs / "source.zip").write_bytes(objects[source])
    manifest = canonical(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:" + "d" * 64},
            "layers": [],
        }
    )
    image_digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
    result = {
        "version": 1,
        "build_id": request["build_id"],
        "request_digest": digest(request),
        "source_digest": source.source_digest,
        "plan_digest": request["plan_digest"],
        "repository": settings.repository,
        "workflow_sha": settings.workflow_sha,
        "platform_code_sha": settings.platform_code_sha,
        "run_id": int(env["GITHUB_RUN_ID"]),
        "platform": "linux/amd64",
        "image_digest": image_digest,
        "image": f"000000000000.dkr.ecr.ap-northeast-2.amazonaws.com/sky-managed@{image_digest}",
    }
    receipt = {
        "version": 1,
        "request_digest": digest(request),
        "image_id": "sha256:" + "d" * 64,
        "archive_digest": "e" * 64,
    }
    export_published(directory / "published-proof", request, result, manifest, receipt)
    return request


def main():
    request = fixture(Path("fixture"))
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
        stream.write(f"build_id={request['build_id']}\nrequest_digest={digest(request)}\n")


if __name__ == "__main__":
    main()
