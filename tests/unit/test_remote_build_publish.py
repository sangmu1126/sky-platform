"""Publish failure boundaries; AWS and Docker calls are simulated."""

import base64
import subprocess
from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import ClientError


@pytest.fixture
def publisher(monkeypatch):
    from scripts import remote_builder

    request = {
        "build_id": "00000000-0000-4000-8000-000000000001",
        "bucket": "sky-artifacts-test",
        "account_id": "123456789012",
        "region": "ap-northeast-2",
        "source_digest": "a" * 64,
        "plan_digest": "b" * 64,
        "repository": "owner/builder",
        "workflow_sha": "c" * 40,
        "platform_code_sha": "d" * 40,
    }
    for name, value in {
        "SKY_ARTIFACTS_BUCKET": request["bucket"],
        "SKY_AWS_ACCOUNT_ID": request["account_id"],
        "AWS_REGION": request["region"],
        "GITHUB_RUN_ID": "42",
    }.items():
        monkeypatch.setenv(name, value)
    sts, ecr, objects = Mock(), Mock(), Mock()
    sts.get_caller_identity.return_value = {"Account": request["account_id"]}
    ecr.get_authorization_token.return_value = {
        "authorizationData": [{"authorizationToken": base64.b64encode(b"AWS:dummy").decode()}]
    }
    missing = ClientError({"Error": {"Code": "ImageNotFoundException"}}, "DescribeImages")
    ecr.describe_images.side_effect = [
        missing,
        {"imageDetails": [{"imageDigest": "sha256:" + "e" * 64}]},
    ]
    with (
        patch.object(remote_builder, "inputs", return_value=(request, None, None)),
        patch("boto3.client", side_effect=lambda service, **_: {"sts": sts, "ecr": ecr}[service]),
        patch.object(remote_builder, "S3BuildObjects", return_value=objects),
        patch.object(remote_builder.subprocess, "run", return_value=Mock(returncode=0)),
        patch.object(remote_builder, "command", return_value="linux/amd64\n") as command,
    ):
        yield remote_builder, ecr, objects, command


@pytest.mark.parametrize(
    "stage", ["existing_tag", "load", "architecture", "tag", "push", "invalid_digest", "result"]
)
def test_publish_failure_logs_out_and_does_not_publish_result(publisher, tmp_path, stage):
    builder, ecr, objects, command = publisher
    if stage == "existing_tag":
        ecr.describe_images.side_effect = None
        ecr.describe_images.return_value = {"imageDetails": []}
    if stage == "result":
        objects.put.side_effect = OSError("result write failed")
    if stage == "invalid_digest":
        ecr.describe_images.side_effect = [
            ClientError({"Error": {"Code": "ImageNotFoundException"}}, "DescribeImages"),
            {"imageDetails": [{"imageDigest": "invalid"}]},
        ]

    def execute(args, **_):
        if args[1] == stage:
            raise OSError("injected failure")
        return "linux/arm64" if stage == "architecture" else "linux/amd64"

    command.side_effect = execute
    with pytest.raises((ValueError, OSError)):
        builder.publish(tmp_path, tmp_path)
    assert command.call_args.args[0][1] == "logout"
    if stage != "result":
        objects.put.assert_not_called()
    if stage in {"existing_tag", "load", "architecture"}:
        assert not any(call.args[0][1] == "push" for call in command.call_args_list)


@pytest.mark.parametrize("cleanup_error", [OSError("logout failed"), subprocess.TimeoutExpired("docker", 30)])
def test_publish_cleanup_failure_preserves_original_error(publisher, tmp_path, cleanup_error):
    builder, _, _, command = publisher

    def execute(args, **_):
        if args[1] == "load":
            raise ValueError("original load failure")
        if args[1] == "logout":
            raise cleanup_error
        return "linux/amd64"

    command.side_effect = execute
    with pytest.raises(ValueError, match="original load failure"):
        builder.publish(tmp_path, tmp_path)
    assert command.call_args.args[0][1] == "logout"


def test_publish_success_records_digest_reference_then_logs_out(publisher, tmp_path):
    builder, _, objects, command = publisher
    builder.publish(tmp_path, tmp_path)
    result = objects.put.call_args.args[1]
    assert result["image"].endswith("/sky-managed@sha256:" + "e" * 64)
    assert result["run_id"] == 42
    assert command.call_args.args[0][1] == "logout"


def test_publish_cleanup_only_failure_fails_job(publisher, tmp_path):
    builder, _, objects, command = publisher

    def execute(args, **_):
        if args[1] == "logout":
            raise OSError("logout failed")
        return "linux/amd64"

    command.side_effect = execute
    with pytest.raises(OSError, match="logout failed"):
        builder.publish(tmp_path, tmp_path)
    objects.put.assert_called_once()


@pytest.mark.parametrize("failure", ["nonzero", "timeout"])
def test_partial_login_failure_still_attempts_logout(publisher, tmp_path, failure):
    builder, ecr, objects, command = publisher
    if failure == "nonzero":
        builder.subprocess.run.return_value.returncode = 1
    else:
        builder.subprocess.run.side_effect = subprocess.TimeoutExpired("docker", 30)
    with pytest.raises((OSError, subprocess.TimeoutExpired)):
        builder.publish(tmp_path, tmp_path)
    ecr.describe_images.assert_not_called()
    objects.put.assert_not_called()
    assert len(command.call_args_list) == 1
    assert command.call_args.args[0][1] == "logout"
