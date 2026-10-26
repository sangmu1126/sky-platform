"""Actual PostgreSQL artifact review lifecycle over combined read-only inspectors."""

import base64
import json
import os
from dataclasses import asdict
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from adapters.state.deployment_reads import PostgresDeploymentReads
from application.deployment_reads import DeploymentReadService
from application.incident_artifact_review import FIELD, HISTORY
from domain.recovery_image import RecoveryImageRegistration
from interfaces.b_runtime import main
from ports.remote_builds import canonical
from tests.contract.test_build_approval import admitted as admitted  # noqa: PLC0414
from tests.contract.test_build_approval import signed_incident as signed_incident  # noqa: PLC0414
from tests.contract.test_deployment_approvals import database as database  # noqa: PLC0414
from tests.contract.test_deployment_approvals import store as store  # noqa: PLC0414
from tests.unit.test_kms_build_key import native
from tests.unit.test_security_hold_cli import configured_cli as configured_cli  # noqa: PLC0414


@pytest.mark.parametrize("change", [None, "key-disabled", "image-missing", "reviewer-revoked", "revision"])
def test_persist_recheck_and_revoke_without_any_activation(
    configured_cli, signed_incident, store, database, tmp_path, monkeypatch, capsys, change
):
    c = signed_incident
    monkeypatch.setenv("SKY_STATE_WORKSPACE", store.operations.workspace)
    memberships = json.loads(os.environ["SKY_MEMBERSHIPS_JSON"])
    memberships["members"][0]["organization_id"] = c.actor.organization_id
    monkeypatch.setenv("SKY_MEMBERSHIPS_JSON", json.dumps(memberships))
    (tmp_path / "key.json").write_bytes(
        canonical(
            {
                "version": 1,
                "key_arn": c.identity.key_arn,
                "public_key_der": base64.b64encode(c.identity.public_key_der).decode(),
            }
        )
    )
    (tmp_path / "bundle.json").write_bytes(canonical(c.bundle))
    (tmp_path / "build.json").write_bytes(
        canonical(
            {
                "version": 1,
                "key_config": "key.json",
                "builder": asdict(c.reader.settings),
                "bundle": "bundle.json",
                "image_digest": c.statement["image_digest"],
                "config_digest": c.statement["config_digest"],
                "run_id": 123,
            }
        )
    )
    r = RecoveryImageRegistration(
        c.actor.organization_id,
        c.record["application_id"],
        c.record["id"],
        "INC-1",
        c.held.record["security_review_boundary"]["id"],
        c.identity.account_id,
        c.identity.region,
        f"{c.identity.account_id}.dkr.ecr.{c.identity.region}.amazonaws.com/recovery@{c.statement['image_digest']}",
        c.statement["config_digest"],
        c.reader.settings.workflow_sha,
        "sha256:" + c.record["source_digest"],
        f"https://github.com/{c.reader.settings.repository}/actions/runs/123",
    )
    (tmp_path / "image.json").write_bytes(canonical({"version": 1, **asdict(r)}))
    _, session, kms, sts = native(c.identity, clock=lambda: datetime.now(UTC))
    ecr = Mock(spec=["meta", "batch_get_image"])
    ecr.meta = SimpleNamespace(region_name=c.identity.region)
    ecr.batch_get_image.return_value = {
        "images": [
            {
                "registryId": c.identity.account_id,
                "repositoryName": "recovery",
                "imageId": {"imageDigest": c.statement["image_digest"]},
                "imageManifest": c.manifest,
                "imageManifestMediaType": "application/vnd.oci.image.manifest.v1+json",
            }
        ],
        "failures": [],
    }
    session.client = Mock(side_effect=lambda name, **_: {"kms": kms, "sts": sts, "ecr": ecr}[name])
    operator_id = c.actor.user_id

    def command(action):
        args = [
            "security-hold",
            action,
            "--job-id",
            c.record["id"],
            "--user-id",
            operator_id,
            "--organization-id",
            c.actor.organization_id,
            "--incident-id",
            "INC-1",
            "--expected-boundary",
            r.boundary_id,
            "--expected-revision",
            str(c.records.load_job(c.record["id"]).revision),
            "--artifact-review-id",
            "c" * 32,
        ]
        if action != "revoke-artifact-review":
            args += [
                "--build-approval-config",
                str(tmp_path / "build.json"),
                "--recovery-image-config",
                str(tmp_path / "image.json"),
            ]
        if action == "approve-artifact-review":
            args += ["--artifact-review-ref", "REVIEW-1", "--confirm-artifact-review"]
        elif action == "revoke-artifact-review":
            args += ["--artifact-review-ref", "REVOKE-1", "--confirm-artifact-review-revocation"]
        return args

    with (
        patch("interfaces.security_hold.RotatingDatabaseConnection", return_value=database),
        patch("boto3.Session", return_value=session),
    ):
        main(command("approve-artifact-review"))
        approved = json.loads(capsys.readouterr().out)
        held = c.records.load_job(c.record["id"])
        assert approved["artifact_review"]["status"] == "approved"
        assert held.record["security_hold"] == c.held.record["security_hold"]
        assert held.record["result"] == c.held.record["result"]
        assert held.record["approval_id"] == c.held.record["approval_id"]
        assert held.record[FIELD]["approved_metadata_revision"] == held.revision
        assert held.record[HISTORY] == []
        public = DeploymentReadService(
            PostgresDeploymentReads(database, workspace=store.operations.workspace)
        ).detail(c.actor, c.record["id"])
        assert FIELD not in public and HISTORY not in public
        if change == "key-disabled":
            kms.describe_key.return_value["KeyMetadata"].update(KeyState="Disabled", Enabled=False)
        elif change == "image-missing":
            ecr.batch_get_image.return_value = {"images": [], "failures": [{"failureCode": "ImageNotFound"}]}
        elif change == "reviewer-revoked":
            original = memberships["members"][0]
            memberships["members"].append({**original, "subject": "second-admin", "user_id": "reviewer2"})
            original["role"] = "viewer"
            monkeypatch.setenv("SKY_MEMBERSHIPS_JSON", json.dumps(memberships))
            operator_id = "reviewer2"
        elif change == "revision":
            c.records.save_job(
                c.record["id"], {**held.record, "external_update": True}, expected_revision=held.revision
            )
            held = c.records.load_job(c.record["id"])
        if change is None:
            main(command("check-artifact-review"))
            checked = json.loads(capsys.readouterr().out)["artifact_review"]
            assert checked["artifact_review_matched"] and checked["read_only"]
            assert not checked["execution_authorized"] and not checked["recovery_authorized"]
        else:
            with pytest.raises(SystemExit) as exc:
                main(command("check-artifact-review"))
            assert exc.value.code == 1 and capsys.readouterr().out == ""
        assert c.records.load_job(c.record["id"]) == held
        with patch("boto3.Session", side_effect=AssertionError("Revocation cannot need AWS")):
            main(command("revoke-artifact-review"))
            revoked = json.loads(capsys.readouterr().out)["artifact_review"]
            assert revoked["status"] == "revoked" and not revoked["hold_released"]
            with pytest.raises(SystemExit) as exc:
                main(command("check-artifact-review"))
            assert exc.value.code == 1 and capsys.readouterr().out == ""
        final = c.records.load_job(c.record["id"])
        assert final.record[FIELD]["revocation_ref"] == "REVOKE-1"
        assert final.record["security_hold"] == c.held.record["security_hold"]


def test_concurrent_artifact_approvals_have_only_one_winner(signed_incident):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from datetime import timedelta

    from application.incident_artifact_review import IncidentArtifactReview
    from ports.state import RecordConflict

    c = signed_incident
    barrier = threading.Barrier(2)
    inspector = Mock()
    inspector.image_registration = SimpleNamespace(
        image="synthetic",
        config_digest=c.statement["config_digest"],
        source_digest="sha256:" + c.record["source_digest"],
        source_revision=c.reader.settings.workflow_sha,
        build_reference="https://github.com/sangmu1126/sky-builder/actions/runs/123",
    )

    def inspect(*_, **options):
        barrier.wait(timeout=10)
        return {
            **dict.fromkeys(
                (
                    "signature_verified",
                    "expected_input_binding_matched",
                    "consumed_deployment_approval_matched",
                    "key_liveness_checked",
                    "ecr_image_verified",
                    "image_signature_approval_binding_matched",
                    "read_only",
                ),
                True,
            ),
            **dict.fromkeys(
                (
                    "recovery_authorized",
                    "current_approval_verified",
                    "faithful_compilation_verified",
                    "image_safety_verified",
                    "state_changed",
                ),
                False,
            ),
            "incident_id": "INC-1",
            "boundary_id": c.held.record["security_review_boundary"]["id"],
            "metadata_revision": c.held.revision,
            "observed_at": datetime.now(UTC).isoformat(),
            "expires_at": (datetime.now(UTC) + timedelta(seconds=300)).isoformat(),
            "build_id": c.statement["build_id"],
            "request_digest": c.statement["request_digest"],
            "key_arn": c.identity.key_arn,
            "public_key_fingerprint": c.identity.fingerprint,
        }

    inspector.inspect.side_effect = inspect
    service = IncidentArtifactReview(
        c.records,
        inspector,
        clock=lambda: datetime.now(UTC).isoformat(),
        revalidate=lambda: c.actor,
        reviewer=lambda _: c.actor,
    )

    def approve(index):
        try:
            return service.approve(
                c.actor,
                c.record["id"],
                review_id=str(index) * 32,
                review_ref="REVIEW-1",
                incident_id="INC-1",
                expected_boundary=c.held.record["security_review_boundary"]["id"],
                expected_revision=c.held.revision,
            )
        except RecordConflict:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(approve, (1, 2)))
    winners = [r for r in results if r is not None]
    assert len(winners) == 1
    final = c.records.load_job(c.record["id"])
    assert final.revision == c.held.revision + 1
    assert final.record[FIELD]["id"] == winners[0]["review_id"]
    assert final.record[HISTORY] == []
    assert final.record["security_hold"] == c.held.record["security_hold"]
