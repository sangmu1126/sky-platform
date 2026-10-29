"""Trusted remote-builder VM composition. No uploaded code runs in this process."""

import hashlib
import json
import os
from dataclasses import fields
from pathlib import Path
from uuid import uuid4

from adapters.build.sandbox_profile import SandboxProfile
from adapters.build.vm_builder import IsolatedVmBuilder
from application.deployment_core import DeploymentPlan
from application.source_artifacts import SourceArtifactService
from domain.access import LoginSource, Principal, Role
from ports.remote_builds import digest
from scripts.observe_security import write_private


def build_in_vm(directory, output, request, artifact, raw_plan, raw_profile):
    if not isinstance(raw_profile, str) or len(raw_profile) > 8192:
        raise ValueError("Bounded operator VM registration required")
    profile = SandboxProfile(**json.loads(raw_profile))
    if (profile.account_id, profile.region) != (request["account_id"], request["region"]):
        raise ValueError("VM registration differs from approved AWS destination")
    path = os.environ.get("SKY_OFFLINE_BUILD_BASE_ARCHIVE", "")
    expected = os.environ.get("SKY_OFFLINE_BUILD_BASE_ARCHIVE_SHA256", "")
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected) or not path:
        raise ValueError("Operator-pinned offline base archive identity required")
    base = Path(path)
    if base.is_symlink() or not base.is_file() or base.stat().st_size > 1024**3:
        raise ValueError("Plain bounded offline base archive required")
    with base.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != expected:
            raise ValueError("Offline base archive changed")
    bases = json.loads(os.environ["SKY_OFFLINE_BUILD_BASES_JSON"])
    payload = (directory / "source.zip").read_bytes()

    class Objects:
        def get(self, selected):
            if selected != artifact:
                raise ValueError("Unexpected source artifact")
            return payload

    principal = Principal(
        request["created_by"], artifact.organization_id, Role.DEPLOYER, LoginSource.CORPORATE_SSO
    )
    plan = DeploymentPlan(
        **{k: v for k, v in raw_plan.items() if k in {f.name for f in fields(DeploymentPlan)}}
    )
    output.mkdir(parents=True, exist_ok=True)
    audit_directory = output.parent / ("sandbox-audit-" + request["build_id"])
    audit_directory.mkdir(mode=0o700, exist_ok=True)

    def audit(event):
        write_private(audit_directory / (uuid4().hex + ".json"), event)

    def guard():
        # Fixed trusted GitHub workflow already checked request provenance in
        # remote_builder.inputs. Never derive authority from context or AI output.
        if (request["account_id"], request["region"]) != (profile.account_id, profile.region):
            raise ValueError("Build AWS registration changed")

    ca = None
    if raw_plan.get("database_profile") == "shared-postgres-v1":
        infrastructure = raw_plan.get("infrastructure_profile", {})
        if infrastructure.get("requirements") != ["database"] or infrastructure.get("database_engines") != [
            "postgresql"
        ]:
            raise ValueError("Prepared PostgreSQL source required")
        ca = Path(__file__).resolve().parents[1] / "src/assets/infra/rds-global-bundle.pem"
    elif raw_plan.get("database_profile") is not None:
        raise ValueError("Unsupported isolated build database profile")
    import boto3

    with SourceArtifactService(Objects()).restore(principal, artifact) as project:
        result = IsolatedVmBuilder(profile, boto3.Session(), guard, lambda *_: None, audit=audit).build(
            project,
            plan,
            output,
            base_archive=base,
            bases=bases,
            extra_ca_bundle=ca,
            build_id=request["build_id"],
        )
    with (output / "image.tar").open("rb") as source:
        archive_digest = hashlib.file_digest(source, "sha256").hexdigest()
    write_private(
        output / "build.json",
        {
            "version": 1,
            "request_digest": digest(request),
            "image_id": result["image_id"],
            "archive_digest": archive_digest,
        },
    )
