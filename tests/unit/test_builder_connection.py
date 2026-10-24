"""Configuration and read-only reference checks; no workflow dispatch or AWS."""

import base64
import json
import subprocess
from unittest.mock import Mock, patch

import pytest

from ports.remote_builds import BuildSettings
from scripts import check_builder_connection as checks


@pytest.fixture
def environment():
    return {
        "SKY_BUILDER_REPOSITORY": "sangmu1126/sky-builder",
        "SKY_BUILDER_REF": "main",
        "SKY_BUILDER_SHA": "a" * 40,
        "SKY_BUILDER_PLATFORM_SHA": "b" * 40,
        "SKY_ARTIFACTS_BUCKET": "sky-artifacts-test",
        "SKY_AWS_ACCOUNT_ID": "123456789012",
        "SKY_AWS_REGION": "ap-northeast-2",
    }


def encoded(data):
    return {"type": "file", "encoding": "base64", "content": base64.b64encode(data).decode()}


def responses():
    return [
        {"sha": "a" * 40},
        encoded((checks.ROOT / "ops/remote-builder/build.yml").read_bytes()),
        {"value": "b" * 40},
        encoded((checks.ROOT / "scripts/remote_builder.py").read_bytes()),
    ]


@pytest.mark.parametrize("workflow", [None, "build.yaml", "personal-build.yml"])
def test_environment_preserves_default_or_explicit_workflow(environment, workflow):
    if workflow is not None:
        environment["SKY_BUILDER_WORKFLOW"] = workflow
    assert BuildSettings.from_environment(environment).workflow == (workflow or "build.yml")


@pytest.mark.parametrize("workflow", ["", "../build.yml", "build.yml?ref=other"])
def test_invalid_workflow_configuration_is_rejected(environment, workflow):
    environment["SKY_BUILDER_WORKFLOW"] = workflow
    with pytest.raises(ValueError):
        BuildSettings.from_environment(environment)


def test_complete_reference_checks_use_pinned_paths_and_explicit_workflow(environment):
    environment["SKY_BUILDER_WORKFLOW"] = "personal-build.yml"
    get = Mock(side_effect=responses())
    checks.check_reference(BuildSettings.from_environment(environment), get)
    assert len(get.call_args_list) == 4
    assert get.call_args_list[1].args[0].endswith("/personal-build.yml?ref=" + "a" * 40)
    assert get.call_args_list[3].args[0].endswith("?ref=" + "b" * 40)


@pytest.mark.parametrize("index", range(4))
def test_reference_mismatch_stops_further_reads(environment, index):
    values = responses()
    values[index] = (
        {"sha": "0" * 40}
        if index == 0
        else ({"value": "0" * 40} if index == 2 else encoded(b"older incompatible implementation"))
    )
    get = Mock(side_effect=values)
    with pytest.raises(ValueError):
        checks.check_reference(BuildSettings.from_environment(environment), get)
    assert get.call_count == index + 1


def test_offline_check_makes_no_subprocess_or_network_calls(environment, capsys):
    with (
        patch.dict(checks.os.environ, environment, clear=True),
        patch.object(checks.subprocess, "run") as run,
    ):
        assert checks.main([]) == 0
    run.assert_not_called()
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "configuration_valid"
    assert result["runtime_verified"] is False
    assert result["github_checked"] is False


def test_github_get_is_explicit_get_only():
    with patch.object(
        checks.subprocess, "run", return_value=Mock(returncode=0, stdout='{"sha":"ok"}')
    ) as run:
        assert checks.github_get("/repos/owner/builder/commits/main") == {"sha": "ok"}
    assert run.call_args.args[0] == ["gh", "api", "--method", "GET", "/repos/owner/builder/commits/main"]


@pytest.mark.parametrize("error", [OSError("private-token"), subprocess.TimeoutExpired("private-token", 30)])
def test_cli_failure_does_not_echo_credentials(environment, error, capsys):
    with (
        patch.dict(checks.os.environ, environment, clear=True),
        patch.object(checks, "check_reference", side_effect=error),
    ):
        assert checks.main(["--github"]) == 1
    text = capsys.readouterr()
    assert "private-token" not in text.out + text.err
    assert json.loads(text.out)["status"] == "check_failed"


def runtime_values():
    return [
        {"value": "123456789012"},
        {"value": "ap-northeast-2"},
        {"value": "sky-artifacts-test"},
        {"value": "arn:aws:iam::123456789012:role/sky/builder"},
    ]


def test_runtime_settings_checks_exact_scope_using_get_only(environment):
    get = Mock(side_effect=runtime_values())
    checks.check_runtime_settings(BuildSettings.from_environment(environment), get)
    assert [c.args[0].rsplit("/", 1)[-1] for c in get.call_args_list] == [
        "AWS_ACCOUNT_ID",
        "AWS_REGION",
        "SKY_ARTIFACTS_BUCKET",
        "AWS_APP_BUILDER_ROLE_ARN",
    ]


@pytest.mark.parametrize("index", range(4))
def test_runtime_scope_mismatch_stops_before_further_reads(environment, index):
    values = runtime_values()
    values[index] = {"value": "unexpected-remote-value"}
    get = Mock(side_effect=values)
    with pytest.raises(checks.ReferenceMismatch) as caught:
        checks.check_runtime_settings(BuildSettings.from_environment(environment), get)
    assert "unexpected-remote-value" not in str(caught.value)
    assert get.call_count == index + 1


@pytest.mark.parametrize(
    "role", [None, "", "arn:aws:iam::999999999999:role/builder", "arn:aws:iam::123456789012:user/admin"]
)
def test_runtime_rejects_missing_cross_account_or_user_role(environment, role):
    values = runtime_values()
    values[-1] = {"value": role}
    with pytest.raises(checks.ReferenceMismatch):
        checks.check_runtime_settings(BuildSettings.from_environment(environment), Mock(side_effect=values))


def test_runtime_check_requires_explicit_github_opt_in():
    with patch.object(checks, "github_get") as get, pytest.raises(SystemExit) as result:
        checks.main(["--runtime-settings"])
    assert result.value.code == 2
    get.assert_not_called()


def test_unreadable_role_variable_names_the_setting_without_response_data(environment):
    get = Mock(side_effect=runtime_values()[:3] + [OSError("sensitive-response")])
    with pytest.raises(checks.ReferenceMismatch) as caught:
        checks.check_runtime_settings(BuildSettings.from_environment(environment), get)
    assert "AWS_APP_BUILDER_ROLE_ARN" in str(caught.value)
    assert "sensitive-response" not in str(caught.value)


def test_cli_reports_runtime_stage_without_echoing_remote_errors(environment, capsys):
    with (
        patch.dict(checks.os.environ, environment, clear=True),
        patch.object(checks, "check_reference"),
        patch.object(checks, "check_runtime_settings", side_effect=OSError("sensitive-response")),
    ):
        assert checks.main(["--github", "--runtime-settings"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["stage"] == "github_runtime_settings"
    assert report["runtime_settings_checked"] is True
    assert "sensitive-response" not in json.dumps(report)


def test_runtime_settings_success_does_not_claim_runtime_readiness(environment, capsys):
    with (
        patch.dict(checks.os.environ, environment, clear=True),
        patch.object(checks, "check_reference"),
        patch.object(checks, "check_runtime_settings") as checked,
    ):
        assert checks.main(["--github", "--runtime-settings"]) == 0
    checked.assert_called_once()
    report = json.loads(capsys.readouterr().out)
    assert report["runtime_settings_checked"] is True
    assert report["runtime_verified"] is False
