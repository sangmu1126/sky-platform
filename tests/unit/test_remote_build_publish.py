"""Untrusted archive publication uses bounded data APIs, never Docker or login tokens."""

import hashlib
import io
import json
import tarfile
from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import ClientError

from adapters.build.registry_image import registry_image
from ports.remote_builds import canonical, digest

BUILD_ID = "00000000-0000-4000-8000-000000000001"
IMAGE_CONFIG = canonical(
    {"os": "linux", "architecture": "amd64", "config": {}, "rootfs": {"type": "layers", "diff_ids": []}}
)
IMAGE_ID = "sha256:" + hashlib.sha256(IMAGE_CONFIG).hexdigest()


@pytest.fixture
def publisher(monkeypatch, tmp_path):
    from scripts import remote_builder

    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)

    request = {
        "build_id": BUILD_ID,
        "bucket": "sky-artifacts-test",
        "account_id": "123456789012",
        "region": "ap-northeast-2",
        "source_digest": "a" * 64,
        "plan_digest": "b" * 64,
        "repository": "owner/builder",
        "workflow_sha": "c" * 40,
        "platform_code_sha": "d" * 40,
    }
    with tarfile.open(tmp_path / "image.tar", "w", format=tarfile.USTAR_FORMAT) as archive:
        config_name = IMAGE_ID.removeprefix("sha256:") + ".json"
        metadata = canonical([{"Config": config_name, "RepoTags": ["sky-build:" + BUILD_ID], "Layers": []}])
        for name, content in ((config_name, IMAGE_CONFIG), ("manifest.json", metadata)):
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    (tmp_path / "build.json").write_bytes(
        canonical(
            {
                "version": 1,
                "request_digest": digest(request),
                "image_id": IMAGE_ID,
                "archive_digest": remote_builder.archive_digest(tmp_path / "image.tar"),
            }
        )
    )
    with registry_image(tmp_path / "image.tar", IMAGE_ID, "sky-build:" + BUILD_ID) as prepared:
        manifest, registry_digest = prepared["manifest"].decode(), prepared["digest"]
    for name, value in {
        "SKY_ARTIFACTS_BUCKET": request["bucket"],
        "SKY_AWS_ACCOUNT_ID": request["account_id"],
        "AWS_REGION": request["region"],
        "GITHUB_RUN_ID": "42",
    }.items():
        monkeypatch.setenv(name, value)
    sts, ecr, objects = Mock(), Mock(), Mock()
    sts.get_caller_identity.return_value = {"Account": request["account_id"]}
    ecr.describe_repositories.return_value = {
        "repositories": [
            {
                "repositoryArn": "arn:aws:ecr:ap-northeast-2:123456789012:repository/sky-managed",
                "imageTagMutability": "IMMUTABLE",
            }
        ]
    }
    ecr.list_tags_for_resource.return_value = {"tags": [{"Key": "app", "Value": "sky"}]}
    ecr.describe_images.side_effect = ClientError(
        {"Error": {"Code": "ImageNotFoundException"}}, "DescribeImages"
    )
    ecr.batch_check_layer_availability.side_effect = lambda **kw: {
        "layers": [{"layerDigest": kw["layerDigests"][0], "layerAvailability": "UNAVAILABLE"}]
    }
    ecr.initiate_layer_upload.return_value = {"partSize": 20 * 1024**2, "uploadId": "test-upload"}
    ecr.upload_layer_part.side_effect = lambda **kw: {
        "registryId": kw["registryId"],
        "repositoryName": kw["repositoryName"],
        "uploadId": kw["uploadId"],
        "lastByteReceived": kw["partLastByte"],
    }
    ecr.complete_layer_upload.side_effect = lambda **kw: {"layerDigest": kw["layerDigests"][0]}
    ecr.put_image.return_value = {"image": {"imageId": {"imageDigest": registry_digest}}}
    ecr.batch_get_image.return_value = {
        "images": [{"imageId": {"imageDigest": registry_digest}, "imageManifest": manifest}]
    }
    with (
        patch.object(remote_builder, "inputs", return_value=(request, None, None)),
        patch("boto3.client", side_effect=lambda service, **_: {"sts": sts, "ecr": ecr}[service]) as clients,
        patch.object(remote_builder, "S3BuildObjects", return_value=objects),
        patch.object(
            remote_builder, "command", side_effect=AssertionError("Publisher invoked Docker")
        ) as command,
    ):
        yield remote_builder, ecr, objects, command, clients


def test_success_uses_data_api_and_persists_digest_before_attestation(publisher, tmp_path):
    builder, ecr, objects, command, _ = publisher
    events = []
    objects.put.side_effect = lambda *args: events.append("persisted")
    with patch(
        "scripts.build_attestation.export_published", side_effect=lambda *args: events.append("attested")
    ):
        builder.publish(tmp_path, tmp_path, attestation_output=tmp_path / "proof")
    assert events == ["persisted", "attested"]
    assert objects.put.call_args.args[1]["image"].endswith(
        "@" + ecr.put_image.call_args.kwargs["imageDigest"]
    )
    ecr.get_authorization_token.assert_not_called()
    command.assert_not_called()
    assert ecr.upload_layer_part.call_args.kwargs["layerPartBlob"] == IMAGE_CONFIG


@pytest.mark.parametrize("change", ["archive", "request", "missing", "duplicate", "oversized"])
def test_altered_artifact_never_accesses_credentials(publisher, tmp_path, change):
    builder, ecr, objects, command, clients = publisher
    receipt = tmp_path / "build.json"
    if change == "archive":
        (tmp_path / "image.tar").write_bytes(b"replaced archive")
    elif change == "request":
        data = json.loads(receipt.read_bytes())
        data["request_digest"] = "0" * 64
        receipt.write_bytes(canonical(data))
    elif change == "missing":
        receipt.unlink()
    elif change == "duplicate":
        receipt.write_bytes(b'{"version":1,' + receipt.read_bytes()[1:])
    else:
        receipt.write_bytes(b" " * 4097)
    with pytest.raises((ValueError, OSError)):
        builder.publish(tmp_path, tmp_path)
    clients.assert_not_called()
    command.assert_not_called()
    objects.put.assert_not_called()
    ecr.get_authorization_token.assert_not_called()


@pytest.mark.parametrize(
    "stage",
    [
        "ownership",
        "mutable",
        "existing",
        "part",
        "blob",
        "manifest",
        "missing",
        "duplicate",
        "failure",
        "digest",
        "altered",
        "result",
    ],
)
def test_failures_never_publish_success_or_execute_image(publisher, tmp_path, stage):
    builder, ecr, objects, command, _ = publisher
    if stage == "ownership":
        ecr.list_tags_for_resource.return_value = {"tags": []}
    elif stage == "mutable":
        ecr.describe_repositories.return_value["repositories"][0]["imageTagMutability"] = "MUTABLE"
    elif stage == "existing":
        ecr.describe_images.side_effect = None
    elif stage == "part":
        ecr.upload_layer_part.side_effect = None
        ecr.upload_layer_part.return_value = {"uploadId": "different"}
    elif stage == "blob":
        ecr.complete_layer_upload.side_effect = None
        ecr.complete_layer_upload.return_value = {"layerDigest": "sha256:" + "0" * 64}
    elif stage == "manifest":
        ecr.put_image.return_value = {}
    elif stage == "missing":
        ecr.batch_get_image.return_value["images"] = []
    elif stage == "duplicate":
        ecr.batch_get_image.return_value["images"] *= 2
    elif stage == "failure":
        ecr.batch_get_image.return_value["failures"] = [{"failureCode": "ImageNotFound"}]
    elif stage == "digest":
        ecr.batch_get_image.return_value["images"][0]["imageId"]["imageDigest"] = "sha256:" + "0" * 64
    elif stage == "altered":
        ecr.batch_get_image.return_value["images"][0]["imageManifest"] += " "
    else:
        objects.put.side_effect = OSError("uncertain result write")
    with patch("scripts.build_attestation.export_published") as export, pytest.raises((ValueError, OSError)):
        builder.publish(tmp_path, tmp_path, attestation_output=tmp_path / "proof")
    export.assert_not_called()
    if stage != "result":
        objects.put.assert_not_called()
    ecr.get_authorization_token.assert_not_called()
    command.assert_not_called()


def test_existing_blobs_are_not_reuploaded(publisher, tmp_path):
    builder, ecr, _, _, _ = publisher
    ecr.batch_check_layer_availability.side_effect = lambda **kw: {
        "layers": [{"layerDigest": kw["layerDigests"][0], "layerAvailability": "AVAILABLE"}]
    }
    builder.publish(tmp_path, tmp_path)
    ecr.initiate_layer_upload.assert_not_called()


@pytest.mark.parametrize("fallback", [False, True])
def test_command_preserves_scoped_environment_on_inspect_fallback(tmp_path, fallback):
    from scripts import remote_builder as builder

    environment, calls = {"DOCKER_CONFIG": str(tmp_path)}, []

    def execute(args, **kwargs):
        calls.append((args, kwargs["env"]))
        fail = fallback and len(calls) == 1
        return (1 if fail else 0), ("unknown flag: --platform" if fail else "linux/amd64")

    with patch("adapters.build.process.bounded_command", side_effect=execute):
        assert (
            builder.command(
                ["docker", "image", "inspect", "--platform", "linux/amd64", "fixture"], env=environment
            )
            == "linux/amd64"
        )
    assert len(calls) == (2 if fallback else 1)
    assert all(selected is environment for _, selected in calls)


def test_required_signature_without_pinned_trust_has_no_aws_effect(publisher, tmp_path, monkeypatch):
    builder, _, objects, command, clients = publisher
    monkeypatch.setenv("SKY_REQUIRE_SIGNED_BUILDS", "true")
    monkeypatch.delenv("SKY_BUILD_SIGNING_TRUST_JSON", raising=False)
    with pytest.raises(ValueError, match="trust"):
        builder.publish(tmp_path, tmp_path)
    clients.assert_not_called()
    objects.put.assert_not_called()
    command.assert_not_called()
