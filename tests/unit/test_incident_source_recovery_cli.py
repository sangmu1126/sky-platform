from unittest.mock import patch

import pytest

from interfaces.b_runtime import main
from tests.unit.test_incident_source_build_cli import arguments as build_arguments
from tests.unit.test_incident_source_build_cli import builder as builder  # noqa: PLC0414
from tests.unit.test_security_hold_cli import configured_cli as configured_cli  # noqa: PLC0414


def arguments(action):
    args = build_arguments("inspect-source-build")
    args[1] = action
    args += ["--source-recovery-id", "a" * 32]
    if action == "approve-source-recovery":
        args += [
            "--confirm-source-recovery-approval",
            "--source-recovery-ref",
            "RECOVER",
            "--allow-public-source-recovery",
            "--operator-github-session",
        ]
    if action == "finalize-source-recovery":
        args += ["--confirm-source-recovery-finalization", "--operator-github-session"]
    if action == "execute-source-recovery":
        args += ["--confirm-source-recovery-execution", "--operator-github-session"]
    return args


@pytest.mark.parametrize(
    "action",
    [
        "approve-source-recovery",
        "execute-source-recovery",
        "inspect-source-recovery",
        "finalize-source-recovery",
    ],
)
def test_recovery_preflight_has_no_provider_or_token_access(
    configured_cli, builder, action, capsys, monkeypatch
):
    if action == "inspect-source-recovery":
        monkeypatch.delenv("SKY_BUILDER_REPOSITORY")
    with (
        patch("boto3.client", side_effect=AssertionError("AWS")),
        patch("subprocess.run", side_effect=AssertionError("Token")),
    ):
        main(arguments(action) + ["--check-config"])
    assert "no AWS/DB/GitHub calls" in capsys.readouterr().out


@pytest.mark.parametrize(
    "change",
    ["confirmation", "mixed-confirm", "bad-id", "zero-seconds", "wrong-account", "missing-postgresql-config"],
)
def test_unsafe_recovery_inputs_rejected_before_provider(configured_cli, builder, change, monkeypatch):
    args = arguments("approve-source-recovery")
    if change == "confirmation":
        args.remove("--confirm-source-recovery-approval")
    elif change == "mixed-confirm":
        args += ["--confirm-source-build-execution"]
    elif change == "bad-id":
        args[args.index("--source-recovery-id") + 1] = "bad"
    elif change == "zero-seconds":
        args += ["--source-recovery-seconds", "0"]
    elif change == "wrong-account":
        monkeypatch.setenv("SKY_AWS_ACCOUNT_ID", "222222222222")
    else:
        args += ["--source-recovery-profile", "postgresql"]
    with patch("boto3.client", side_effect=AssertionError("AWS")), pytest.raises(SystemExit) as result:
        main(args + ["--check-config"])
    assert result.value.code == 2


def test_execution_cannot_change_public_access_consent(configured_cli, builder):
    with pytest.raises(SystemExit) as result:
        main(arguments("execute-source-recovery") + ["--allow-public-source-recovery", "--check-config"])
    assert result.value.code == 2


def test_inspection_rejects_provider_configuration(configured_cli):
    with pytest.raises(SystemExit) as result:
        main(arguments("inspect-source-recovery") + ["--operator-github-session", "--check-config"])
    assert result.value.code == 2
