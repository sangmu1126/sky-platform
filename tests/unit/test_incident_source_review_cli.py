from unittest.mock import patch

import pytest

from interfaces.b_runtime import main
from ports.artifacts import SourceArtifact
from ports.remote_builds import canonical
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
        "--expected-revision",
        "2",
        "--expected-boundary",
        "b" * 32,
        "--source-review-id",
        "c" * 32,
    ]
    if action == "approve-source-review":
        args += ["--confirm-source-review", "--source-review-ref", "REVIEW-1"]
    if action == "supersede-source-review":
        args += [
            "--confirm-source-review-supersession",
            "--source-review-ref",
            "SUCCESSOR-1",
            "--predecessor-review-id",
            "b" * 32,
        ]
    if action == "revoke-source-review":
        args += ["--confirm-source-review-revocation", "--source-review-ref", "REVOKE-1"]
    return args


@pytest.fixture
def descriptor(tmp_path, monkeypatch):
    monkeypatch.setenv("SKY_ARTIFACTS_BUCKET", "sky-source-test")
    monkeypatch.setenv("SKY_AWS_ACCOUNT_ID", "111111111111")
    path = tmp_path / "source.json"
    path.write_bytes(
        canonical(SourceArtifact("org1", "game", "d" * 32, "original", "e" * 64, 123, "f" * 64).record())
    )
    return str(path)


@pytest.mark.parametrize(
    "action",
    [
        "approve-source-review",
        "supersede-source-review",
        "check-source-review",
        "inspect-source-review",
        "revoke-source-review",
    ],
)
def test_preflight_has_no_provider_calls(configured_cli, descriptor, action, monkeypatch, capsys):
    args = arguments(action)
    if action in {"approve-source-review", "supersede-source-review", "check-source-review"}:
        args += ["--recovery-source-config", descriptor]
    else:
        monkeypatch.delenv("SKY_ARTIFACTS_BUCKET")
        monkeypatch.delenv("SKY_AWS_ACCOUNT_ID")
    with (
        patch("boto3.client", side_effect=AssertionError("AWS")),
        patch(
            "interfaces.incident_source_review.RotatingDatabaseConnection", side_effect=AssertionError("DB")
        ),
    ):
        main(args + ["--check-config"])
    assert "no AWS/DB calls" in capsys.readouterr().out


@pytest.mark.parametrize(
    "extra",
    [
        ["--confirm-hold"],
        ["--source-review-seconds", "0"],
        ["--confirm-source-review-revocation"],
        ["--recovery-seconds", "0"],
    ],
)
def test_mixed_or_invalid_options_fail_before_clients(configured_cli, descriptor, extra):
    with patch("boto3.client", side_effect=AssertionError("AWS")), pytest.raises(SystemExit) as result:
        main(
            arguments("approve-source-review")
            + ["--recovery-source-config", descriptor, "--check-config"]
            + extra
        )
    assert result.value.code == 2


@pytest.mark.parametrize("action", ["inspect-source-review", "revoke-source-review"])
def test_metadata_actions_reject_source_loading(configured_cli, descriptor, action):
    with pytest.raises(SystemExit) as result:
        main(arguments(action) + ["--recovery-source-config", descriptor, "--check-config"])
    assert result.value.code == 2


def test_wrong_storage_account_rejected(configured_cli, descriptor, monkeypatch):
    monkeypatch.setenv("SKY_AWS_ACCOUNT_ID", "222222222222")
    with pytest.raises(SystemExit) as result:
        main(arguments("check-source-review") + ["--recovery-source-config", descriptor, "--check-config"])
    assert result.value.code == 2


def test_provider_errors_never_print_secret(configured_cli, capsys):
    with (
        patch(
            "interfaces.incident_source_review.RotatingDatabaseConnection",
            side_effect=OSError("DO-NOT-PRINT"),
        ),
        pytest.raises(SystemExit) as result,
    ):
        main(arguments("inspect-source-review"))
    assert result.value.code == 1
    assert "DO-NOT-PRINT" not in capsys.readouterr().err


@pytest.mark.parametrize("change", ["no-confirm", "missing-predecessor", "bad-predecessor", "mixed-confirm"])
def test_supersession_requires_its_own_confirmation_and_predecessor(configured_cli, descriptor, change):
    args = arguments("supersede-source-review") + ["--recovery-source-config", descriptor, "--check-config"]
    if change == "no-confirm":
        args.remove("--confirm-source-review-supersession")
    elif change == "missing-predecessor":
        index = args.index("--predecessor-review-id")
        del args[index : index + 2]
    elif change == "bad-predecessor":
        args[args.index("--predecessor-review-id") + 1] = "bad"
    else:
        args += ["--confirm-source-review"]
    with patch("boto3.client", side_effect=AssertionError("AWS")), pytest.raises(SystemExit) as result:
        main(args)
    assert result.value.code == 2


@pytest.mark.parametrize("action", ["check-source-review", "inspect-source-review", "revoke-source-review"])
def test_read_and_revoke_cannot_smuggle_supersession(configured_cli, descriptor, action):
    args = arguments(action) + ["--predecessor-review-id", "b" * 32, "--check-config"]
    if action == "check-source-review":
        args += ["--recovery-source-config", descriptor]
    with pytest.raises(SystemExit) as result:
        main(args)
    assert result.value.code == 2
