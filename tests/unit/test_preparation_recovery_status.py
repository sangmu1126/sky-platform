"""Status inspection validates operators without recovery/provider configuration."""

from contextlib import contextmanager
from dataclasses import replace
from unittest.mock import Mock, patch

import pytest

from domain.access import Role
from interfaces.b_runtime import main
from interfaces.preparation_recovery_status import recovery_status
from tests.unit.test_deployment_writes import principal
from tests.unit.test_preparation_recovery_cli import arguments

pytest_plugins = [
    "tests.unit.test_dedicated_database_admission",
    "tests.unit.test_database_promotion_workflow",
]


def status_arguments(operation=None, attempt=None, version=None):
    args = arguments()
    args[args.index("--mode") + 1] = "dedicated-database-recovery-status"
    if operation:
        args[args.index("--operation-id") + 1] = operation
    if attempt is None and version is None:
        for option in ("--attempt-id", "--expected-operation-version"):
            index = args.index(option)
            del args[index : index + 2]
    else:
        args[args.index("--attempt-id") + 1] = attempt
        args[args.index("--expected-operation-version") + 1] = str(version)
    return args


@contextmanager
def status_actor(actor=None):
    with (
        patch("interfaces.preparation_recovery_status.load_hosted_identity", return_value=Mock()),
        patch(
            "interfaces.preparation_recovery_status.current_membership",
            return_value=actor or principal(role=Role.ADMIN),
        ),
    ):
        yield


def test_status_config_check_requires_no_recovery_registration_or_cloud(admission_setup, monkeypatch, capsys):
    monkeypatch.delenv("SKY_PREPARATION_RECOVERY_JSON", raising=False)
    monkeypatch.delenv("SKY_OPERATING_REVIEW_POLICIES_JSON", raising=False)
    with (
        status_actor(),
        patch("boto3.Session", side_effect=AssertionError("Cloud session")),
        patch("boto3.client", side_effect=AssertionError("Cloud client")),
        patch(
            "interfaces.preparation_recovery_status.RotatingDatabaseConnection",
            side_effect=AssertionError("DB"),
        ),
    ):
        main(status_arguments() + ["--check-config"])
    assert "preparation recovery status; no AWS/DB calls" in capsys.readouterr().out


@pytest.mark.parametrize(
    "change",
    ["attempt_only", "version_only", "invalid_version", "role", "provisioning", "registration", "once"],
)
def test_status_rejects_partial_original_request_and_mutation_settings(admission_setup, change):
    args = status_arguments()
    if change == "attempt_only":
        args.extend(["--attempt-id", "22222222-2222-4222-8222-222222222222"])
    elif change in {"version_only", "invalid_version"}:
        args.extend(["--expected-operation-version", "1" if change == "version_only" else "0"])
    elif change == "provisioning":
        args.extend(["--dedicated-config", "not-used.json"])
    elif change == "registration":
        args.extend(["--recovery-config", "not-used.json"])
    elif change == "once":
        args.remove("--once")
    with (
        status_actor(principal(role=Role.VIEWER) if change == "role" else None),
        patch(
            "interfaces.preparation_recovery_status.RotatingDatabaseConnection",
            side_effect=AssertionError("DB"),
        ),
        pytest.raises(SystemExit) as error,
    ):
        main(args + ["--check-config"])
    assert error.value.code == 2


@pytest.mark.parametrize("matching", [True, False])
def test_resolution_confirmation_is_separate_from_current_operation_outcome(flow, matching):
    _, records, _, operations, _, operation, _, _ = flow
    resolution = {
        "outcome": "resume",
        "attempt_id": operation.attempt_id,
        "row_version": operation.row_version,
    }
    operations.get.return_value = replace(
        operation,
        status="failed",
        external_receipt={"resolution": resolution, "password": "never-disclose"},
    )
    value = recovery_status(
        records,
        operations,
        principal(role=Role.ADMIN),
        operation.id,
        original_attempt=operation.attempt_id,
        original_version=operation.row_version if matching else operation.row_version + 1,
    )
    assert value["status"] == "failed"
    assert value["original_recovery_request"] == ("recorded" if matching else "unconfirmed")
    assert "never-disclose" not in str(value) and "resolution" not in value
    assert value["observed_only"] is True


@pytest.mark.parametrize(
    "reference,expected",
    [("none", "not_requested"), ("same", "not_recorded_at_snapshot"), ("other", "unconfirmed")],
)
def test_unresolved_request_is_reported_only_as_a_snapshot_without_retry(flow, reference, expected):
    _, records, _, operations, _, operation, _, _ = flow
    operations.get.return_value = replace(operation, status="needs_attention", external_pending=True)
    value = recovery_status(
        records,
        operations,
        principal(role=Role.ADMIN),
        operation.id,
        original_attempt=None if reference == "none" else operation.attempt_id,
        original_version=None if reference == "none" else operation.row_version + (reference == "other"),
    )
    assert value["original_recovery_request"] == expected
    operations.resolve_attention.assert_not_called()
    operations.admit.assert_called_once()  # Fixture admission only.
