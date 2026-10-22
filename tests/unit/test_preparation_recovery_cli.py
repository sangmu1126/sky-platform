"""Recovery registration and explicit CLI validation perform no cloud/DB calls."""

import json
from contextlib import contextmanager
from unittest.mock import Mock, patch

import pytest

from domain.access import Role
from interfaces.b_runtime import main
from interfaces.dedicated_database_recovery import load_recovery_registration
from tests.unit.test_deployment_writes import principal

pytest_plugins = ["tests.unit.test_dedicated_database_admission"]

SCOPE = {"account_id": "111111111111", "region": "ap-northeast-2"}


def registration():
    return {
        "version": 1,
        "cluster_arn": "arn:aws:ecs:ap-northeast-2:111111111111:cluster/sky-worker",
        "profile": {
            "profile_id": "dedicated-rds-create-only-v1",
            "task_definition_arn": "arn:aws:ecs:ap-northeast-2:111111111111:task-definition/sky-worker:7",
            "images": {"worker": "sha256:" + "c" * 64},
        },
        "lifetime_seconds": 120,
    }


def arguments(
    operation="11111111-1111-4111-8111-111111111111",
    attempt="22222222-2222-4222-8222-222222222222",
    version=4,
):
    return [
        "worker",
        "--mode",
        "dedicated-database-recover",
        "--once",
        "--operation-id",
        operation,
        "--attempt-id",
        attempt,
        "--expected-operation-version",
        str(version),
        "--recovery-user-id",
        "user1",
        "--recovery-organization-id",
        "org1",
    ]


@contextmanager
def configured_actor(role=Role.ADMIN):
    with (
        patch("interfaces.dedicated_database_recovery.load_hosted_identity", return_value=Mock()),
        patch("interfaces.dedicated_database_recovery.current_membership", return_value=principal(role=role)),
    ):
        yield


def test_recovery_registration_environment_and_file_are_explicit(monkeypatch, tmp_path):
    monkeypatch.setenv("SKY_PREPARATION_RECOVERY_JSON", json.dumps(registration()))
    loaded = load_recovery_registration(None, **SCOPE)
    assert loaded.profile.record() == registration()["profile"]
    path = tmp_path / "recovery.json"
    path.write_text(json.dumps(registration()))
    with pytest.raises(ValueError, match="not both"):
        load_recovery_registration(str(path), **SCOPE)
    monkeypatch.delenv("SKY_PREPARATION_RECOVERY_JSON")
    assert load_recovery_registration(str(path), **SCOPE) == loaded
    with pytest.raises(ValueError):
        load_recovery_registration(None, **SCOPE)


@pytest.mark.parametrize(
    "change",
    [
        "version",
        "lifetime",
        "extra",
        "account",
        "region",
        "definition",
        "tag",
        "profile",
        "duplicate",
        "oversize",
    ],
)
def test_unreviewed_or_malformed_registration_is_rejected(monkeypatch, change):
    value = registration()
    if change == "version":
        value["version"] = True
    elif change == "lifetime":
        value["lifetime_seconds"] = 301
    elif change == "extra":
        value["command"] = "not-allowed"
    elif change in {"account", "region"}:
        value["cluster_arn"] = value["cluster_arn"].replace(
            "111111111111" if change == "account" else "ap-northeast-2",
            "222222222222" if change == "account" else "us-east-1",
        )
    elif change == "definition":
        value["profile"]["task_definition_arn"] = "mutable-family"
    elif change == "tag":
        value["profile"]["images"]["worker"] = "latest"
    elif change == "profile":
        value["profile"]["profile_id"] = "arbitrary-mutations"
    raw = json.dumps(value)
    if change == "duplicate":
        raw = '{"version":1,' + raw[1:]
    elif change == "oversize":
        raw = "x" * 16385
    monkeypatch.setenv("SKY_PREPARATION_RECOVERY_JSON", raw)
    with pytest.raises(ValueError):
        load_recovery_registration(None, **SCOPE)


def test_check_config_does_not_connect_or_construct_cloud_clients(admission_setup, monkeypatch, capsys):
    monkeypatch.setenv("SKY_PREPARATION_RECOVERY_JSON", json.dumps(registration()))
    with (
        configured_actor(),
        patch("boto3.client", side_effect=AssertionError("AWS")),
        patch("boto3.Session", side_effect=AssertionError("AWS session")),
        patch(
            "interfaces.dedicated_database_recovery.RotatingDatabaseConnection",
            side_effect=AssertionError("DB"),
        ),
    ):
        main(arguments() + ["--check-config"])
    assert "explicit preparation recovery; no AWS/DB calls" in capsys.readouterr().out


@pytest.mark.parametrize("change", ["once", "operation", "version", "actor", "initialize", "role", "mode"])
def test_recovery_requires_bounded_original_operation_and_admin(admission_setup, monkeypatch, change):
    monkeypatch.setenv("SKY_PREPARATION_RECOVERY_JSON", json.dumps(registration()))
    args = arguments()
    if change == "once":
        args.remove("--once")
    elif change in {"operation", "version", "actor"}:
        key = {
            "operation": "--operation-id",
            "version": "--expected-operation-version",
            "actor": "--recovery-user-id",
        }[change]
        args[args.index(key) + 1] = "0" if change == "version" else "../invalid"
    elif change == "initialize":
        args.append("--initialize-pool")
    elif change == "mode":
        args[args.index("--mode") + 1] = "operating-review"
    with (
        configured_actor(Role.DEPLOYER if change == "role" else Role.ADMIN),
        patch(
            "interfaces.dedicated_database_recovery.RotatingDatabaseConnection",
            side_effect=AssertionError("DB"),
        ),
        pytest.raises(SystemExit) as error,
    ):
        main(args + ["--check-config"])
    assert error.value.code == 2
