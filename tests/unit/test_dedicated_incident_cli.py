"""Dedicated config is explicit, app-bound and validation never creates clients."""

import json
from dataclasses import asdict
from datetime import UTC, datetime
from unittest.mock import Mock, patch

import pytest

from application.security_hold import SecurityHold
from domain.access import Role
from interfaces.b_runtime import main
from interfaces.incident_database_registration import load_dedicated_incident_registration
from interfaces.shared_database_worker import load_pool_configuration
from tests.unit.test_deployment_writes import Records, principal
from tests.unit.test_incident_database_cli import command

pytest_plugins = ["tests.unit.test_security_hold_cli", "tests.unit.test_shared_database_worker_cli"]


def registration_file(configuration, tmp_path):
    path = tmp_path / "dedicated-incident.json"
    pool_path = configuration[0]
    source, _ = load_pool_configuration(pool_path)
    document = {
        "version": 1,
        "settings": {
            "database_security_group": "sg-33333333",
            "subnet_group": "sky-subnets",
            "parameter_group": "sky-tls",
            "instance_class": "db.t4g.small",
            "engine_version": "17.9",
            "storage_gb": 20,
            "multi_az": False,
        },
        "binding": {
            "organization_id": "org1",
            "application_id": "game",
            "role": "dedicated_workload",
            "account_id": source.pool.account_id,
            "region": source.pool.region,
            "instance_id": "sky-game-dedicated",
            "database_name": "game",
            "owner_ref": "app-game",
        },
        "operation_id": "11111111-1111-4111-8111-111111111111",
        "plan_id": "DBP-" + "a" * 16,
        "resource_id": "db-TARGET",
        "admin_secret_arn": f"arn:aws:secretsmanager:{source.pool.region}:{source.pool.account_id}:secret:dedicated-test01",
        "connection_limit": 5,
    }
    path.write_text(json.dumps(document))
    return path, document, source


@pytest.mark.parametrize("action", ["restrict-database", "inspect-database"])
def test_dedicated_check_config_has_no_clients(configured_cli, configuration, tmp_path, action, capsys):
    path, _, _ = registration_file(configuration, tmp_path)
    with (
        patch("interfaces.security_hold.AwsDedicatedIncidentDatabase", side_effect=AssertionError("AWS")),
        patch("interfaces.security_hold.RotatingDatabaseConnection", side_effect=AssertionError("SQL")),
    ):
        main(command(configuration[0], action) + ["--dedicated-incident-config", str(path), "--check-config"])
    assert "no AWS/DB calls" in capsys.readouterr().out


@pytest.mark.parametrize(
    "change", ["version", "duplicate", "foreign-account", "state-db", "source-secret", "size", "mixed-env"]
)
def test_malformed_or_unbounded_registration_rejected(configuration, tmp_path, monkeypatch, change):
    path, document, source = registration_file(configuration, tmp_path)
    if change == "version":
        document["version"] = True
    elif change == "duplicate":
        path.write_text('{"version":1,' + json.dumps(document)[1:])
    elif change == "foreign-account":
        document["binding"]["account_id"] = "222222222222"
    elif change == "state-db":
        document["binding"]["database_name"] = "sky_state"
    elif change == "source-secret":
        document["admin_secret_arn"] = source.admin_secret_arn
    elif change == "size":
        path.write_text(" " * 32769)
    else:
        monkeypatch.setenv("SKY_DEDICATED_INCIDENT_JSON", json.dumps(document))
    if change not in {"duplicate", "size"}:
        path.write_text(json.dumps(document))
    with pytest.raises((ValueError, TypeError)):
        load_dedicated_incident_registration(path, source)


def test_current_dedicated_binding_routes_to_registered_provider(
    configured_cli, configuration, tmp_path, capsys
):
    path, _document, source = registration_file(configuration, tmp_path)
    binding = load_dedicated_incident_registration(path, source).binding
    records = Records()
    records.job["workload_database_binding"] = asdict(binding)
    SecurityHold(records).place(
        principal(role=Role.ADMIN),
        records.job["id"],
        incident_id="INC-1",
        reason="suspected_compromise",
        now=datetime.now(UTC).isoformat(),
    )
    boundary = records.job["security_review_boundary"]["id"]
    adapter = Mock(binding=binding)
    adapter.restrict.return_value = {"binding": asdict(binding), "login_enabled": False}
    provider = Mock()
    provider.incident_restriction.return_value = adapter
    with (
        patch("interfaces.security_hold.RotatingDatabaseConnection", return_value=Mock()),
        patch("interfaces.security_hold.check_database_ready"),
        patch("interfaces.security_hold.PostgresDeploymentRecordStore", return_value=records),
        patch(
            "interfaces.security_hold.AwsSharedDatabaseAllocator",
            side_effect=AssertionError("Shared fallback"),
        ),
        patch("interfaces.security_hold.AwsDedicatedIncidentDatabase", return_value=provider),
    ):
        main(
            command(configuration[0], revision=records.revision, boundary=boundary)
            + ["--dedicated-incident-config", str(path)]
        )
    assert json.loads(capsys.readouterr().out)["database_restriction"]["phase"] == "verified"
    provider.incident_restriction.assert_called_once()


@pytest.mark.parametrize("missing", [True, False])
def test_missing_or_other_app_registration_rejected_without_aws(
    configured_cli, configuration, tmp_path, missing
):
    path, document, source = registration_file(configuration, tmp_path)
    registration = load_dedicated_incident_registration(path, source)
    records = Records()
    records.job["workload_database_binding"] = asdict(registration.binding)
    if not missing:
        document["binding"]["application_id"] = "other"
        path.write_text(json.dumps(document))
    args = command(configuration[0])
    if not missing:
        args += ["--dedicated-incident-config", str(path)]
    with (
        patch("interfaces.security_hold.RotatingDatabaseConnection", return_value=Mock()),
        patch("interfaces.security_hold.check_database_ready"),
        patch("interfaces.security_hold.PostgresDeploymentRecordStore", return_value=records),
        patch("interfaces.security_hold.AwsDedicatedIncidentDatabase", side_effect=AssertionError("AWS")),
        pytest.raises(SystemExit) as failure,
    ):
        main(args)
    assert failure.value.code == 1 and records.save_calls == 0
