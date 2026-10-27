from unittest.mock import patch

import pytest

from interfaces.b_runtime import main
from tests.unit.test_incident_source_build import APPROVAL, BUILD
from tests.unit.test_security_hold_cli import configured_cli as configured_cli  # noqa: PLC0414


def arguments(action):
    args = [
        "security-hold",
        action,
        "--job-id",
        "a" * 16,
        "--user-id",
        "user1",
        "--organization-id",
        "org1",
        "--incident-id",
        "INC-1",
        "--expected-boundary",
        "b" * 32,
        "--expected-revision",
        "2",
        "--source-build-approval-id",
        APPROVAL,
    ]
    if action == "approve-source-build":
        args += [
            "--confirm-source-build-approval",
            "--source-build-ref",
            "BUILD-1",
            "--source-build-id",
            BUILD,
            "--source-review-id",
            "c" * 32,
        ]
    elif action == "revoke-source-build":
        args += ["--confirm-source-build-revocation", "--source-build-ref", "REVOKE-1"]
    return args


@pytest.fixture
def builder(monkeypatch):
    for key, value in {
        "SKY_ARTIFACTS_BUCKET": "source-bucket",
        "SKY_AWS_ACCOUNT_ID": "111111111111",
        "SKY_BUILDER_REPOSITORY": "owner/builder",
        "SKY_BUILDER_REF": "main",
        "SKY_BUILDER_SHA": "1" * 40,
        "SKY_BUILDER_PLATFORM_SHA": "2" * 40,
    }.items():
        monkeypatch.setenv(key, value)


@pytest.mark.parametrize(
    "action", ["approve-source-build", "check-source-build", "inspect-source-build", "revoke-source-build"]
)
def test_build_preflight_never_creates_clients(configured_cli, builder, action, monkeypatch, capsys):
    if action in {"inspect-source-build", "revoke-source-build"}:
        monkeypatch.delenv("SKY_ARTIFACTS_BUCKET")
        monkeypatch.delenv("SKY_BUILDER_REPOSITORY")
    with (
        patch("boto3.client", side_effect=AssertionError("AWS")),
        patch(
            "interfaces.incident_source_build.RotatingDatabaseConnection", side_effect=AssertionError("DB")
        ),
    ):
        main(arguments(action) + ["--check-config"])
    assert "no AWS/DB calls" in capsys.readouterr().out


@pytest.mark.parametrize(
    "extra",
    [
        ["--confirm-source-review"],
        ["--confirm-recovery-execution"],
        ["--source-build-seconds", "0"],
        ["--confirm-source-build-revocation"],
        ["--recovery-seconds", "0"],
        ["--predecessor-review-id", "d" * 32],
    ],
)
def test_invalid_or_mixed_build_consent_has_no_side_effects(configured_cli, builder, extra):
    with patch("boto3.client", side_effect=AssertionError("AWS")), pytest.raises(SystemExit) as result:
        main(arguments("approve-source-build") + extra + ["--check-config"])
    assert result.value.code == 2


@pytest.mark.parametrize("change", ["confirmation", "account", "workflow-pin", "build-id", "review-id"])
def test_unpinned_or_unconfirmed_consent_is_rejected(configured_cli, builder, monkeypatch, change):
    args = arguments("approve-source-build")
    if change == "confirmation":
        args.remove("--confirm-source-build-approval")
    elif change == "account":
        monkeypatch.setenv("SKY_AWS_ACCOUNT_ID", "222222222222")
    elif change == "workflow-pin":
        monkeypatch.setenv("SKY_BUILDER_SHA", "main")
    elif change == "build-id":
        args[args.index("--source-build-id") + 1] = "bad"
    else:
        args[args.index("--source-review-id") + 1] = "bad"
    with pytest.raises(SystemExit) as result:
        main(args + ["--check-config"])
    assert result.value.code == 2


def test_other_actions_reject_build_consent_options(configured_cli):
    args = [
        "security-hold",
        "status",
        "--job-id",
        "a" * 16,
        "--user-id",
        "user1",
        "--organization-id",
        "org1",
        "--source-build-approval-id",
        APPROVAL,
        "--check-config",
    ]
    with pytest.raises(SystemExit) as result:
        main(args)
    assert result.value.code == 2


def test_provider_error_is_sanitized(configured_cli, capsys):
    with (
        patch(
            "interfaces.incident_source_build.RotatingDatabaseConnection", side_effect=OSError("DO-NOT-PRINT")
        ),
        pytest.raises(SystemExit) as result,
    ):
        main(arguments("inspect-source-build"))
    assert result.value.code == 1
    assert "DO-NOT-PRINT" not in capsys.readouterr().err


def test_opt_in_migration_database_error_is_sanitized(configured_cli, builder, capsys):
    from unittest.mock import Mock

    from psycopg import OperationalError

    with (
        patch("interfaces.b_runtime.migration_steps"),
        patch("interfaces.b_runtime.run_migrations"),
        patch("adapters.state.postgres.RotatingDatabaseConnection", return_value=Mock()),
        patch(
            "adapters.state.source_build_approvals.PostgresSourceBuildApprovals.initialize",
            side_effect=OperationalError("DO-NOT-PRINT"),
        ),
        pytest.raises(SystemExit) as result,
    ):
        main(["migrate", "--source-build-approvals"])
    assert result.value.code == 1
    assert "DO-NOT-PRINT" not in capsys.readouterr().err
