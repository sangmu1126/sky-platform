"""Trusted operator command admission and scope: no arbitrary DB/role inputs."""

import json
from dataclasses import asdict
from unittest.mock import Mock, patch

import pytest

from application.security_hold import SecurityHold
from domain.access import Role
from domain.shared_database import PoolAllocationRequest
from interfaces.b_runtime import main
from interfaces.shared_database_worker import load_pool_configuration
from tests.unit.test_deployment_writes import Records, principal
from tests.unit.test_security_hold_cli import arguments

pytest_plugins = [
    "tests.unit.test_security_hold_cli",
    "tests.unit.test_shared_database_worker_cli",
]


def command(path, action="restrict-database", revision=1, boundary="a" * 32):
    result = arguments(action) + [
        "--pool-config",
        str(path),
        "--incident-id",
        "INC-1",
        "--expected-revision",
        str(revision),
        "--expected-boundary",
        boundary,
    ]
    if action == "restrict-database":
        result += ["--confirm-database-restriction"]
    else:
        result += ["--expected-operation-id", "b" * 32]
    return result


@pytest.mark.parametrize("action", ["restrict-database", "inspect-database"])
def test_check_config_never_contacts_cloud_or_sql(configured_cli, configuration, action, capsys):
    with (
        patch("interfaces.security_hold.AwsSharedDatabaseAllocator", side_effect=AssertionError("AWS")),
        patch("interfaces.security_hold.RotatingDatabaseConnection", side_effect=AssertionError("SQL")),
    ):
        main(command(configuration[0], action) + ["--check-config"])
    assert "no AWS/DB calls" in capsys.readouterr().out


@pytest.mark.parametrize("change", ["confirmation", "operation", "revision", "boundary", "release", "host"])
def test_invalid_options_rejected_without_clients(configured_cli, configuration, change):
    args = command(configuration[0])
    if change == "confirmation":
        args.remove("--confirm-database-restriction")
    elif change == "operation":
        args += ["--expected-operation-id", "b" * 32]
    elif change in {"revision", "boundary"}:
        args[args.index("--expected-" + change) + 1] = "0"
    elif change == "release":
        args += ["--confirm-false-positive"]
    else:
        args += ["--database-host", "untrusted.example"]
    with (
        patch("interfaces.security_hold.AwsSharedDatabaseAllocator", side_effect=AssertionError("AWS")),
        pytest.raises(SystemExit) as failure,
    ):
        main(args + ["--check-config"])
    assert failure.value.code == 2


def test_cli_records_intent_before_sql_and_status_exposes_operation_for_inspection(
    configured_cli,
    configuration,
    capsys,
):
    settings, _ = load_pool_configuration(configuration[0])
    binding = PoolAllocationRequest(settings.pool, "org1", "game").binding()
    records = Records()
    records.job.update(application_id="game", workload_database_binding=asdict(binding))
    actor = principal(role=Role.ADMIN)
    held = SecurityHold(records).place(
        actor,
        records.job["id"],
        incident_id="INC-1",
        reason="suspected_compromise",
        now="2026-10-24T00:00:00+00:00",
    )
    del held
    boundary = records.job["security_review_boundary"]["id"]
    revision = records.revision
    adapter = Mock(binding=binding)

    def restrict(*, guard):
        guard()
        assert records.job["security_database_restriction"]["phase"] == "applying"
        return {"binding": asdict(binding), "login_enabled": False}

    adapter.restrict.side_effect = restrict
    aws = Mock()
    aws.incident_restriction.return_value = adapter
    with (
        patch("interfaces.security_hold.RotatingDatabaseConnection", return_value=Mock()),
        patch("interfaces.security_hold.check_database_ready"),
        patch("interfaces.security_hold.PostgresDeploymentRecordStore", return_value=records),
        patch("interfaces.security_hold.AwsSharedDatabaseAllocator", return_value=aws),
    ):
        main(command(configuration[0], revision=revision, boundary=boundary))
        report = json.loads(capsys.readouterr().out)
        assert report["database_restriction"]["phase"] == "verified"
        main(arguments())
        status = json.loads(capsys.readouterr().out)
        assert (
            status["database_restriction"]["operation_id"] == report["database_restriction"]["operation_id"]
        )
    assert adapter.restrict.call_count == 1
    assert aws.incident_restriction.call_args.kwargs.keys() == {"guard", "connection_guard"}


def test_factory_failure_never_leaks_diagnostics(configured_cli, configuration, capsys):
    records = Records()
    settings, _ = load_pool_configuration(configuration[0])
    records.job.update(
        application_id="game",
        workload_database_binding=asdict(PoolAllocationRequest(settings.pool, "org1", "game").binding()),
    )
    with (
        patch("interfaces.security_hold.RotatingDatabaseConnection", return_value=Mock()),
        patch("interfaces.security_hold.check_database_ready"),
        patch("interfaces.security_hold.PostgresDeploymentRecordStore", return_value=records),
        patch("interfaces.security_hold.AwsSharedDatabaseAllocator", side_effect=OSError("private-password")),
        pytest.raises(SystemExit) as failure,
    ):
        main(command(configuration[0]))
    assert failure.value.code == 1
    assert "private-password" not in capsys.readouterr().err
    assert records.save_calls == 0
