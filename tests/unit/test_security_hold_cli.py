import json
import os
from dataclasses import replace
from unittest.mock import Mock, patch

import pytest

from application.security_hold import SecurityHold
from domain.access import Role
from interfaces.b_runtime import main
from interfaces.service import main as service_main
from tests.unit.test_deployment_writes import Records, principal
from tests.unit.test_operating_review import ID

pytest_plugins = ["tests.unit.test_operating_review"]

ISSUER = "https://cognito-idp.ap-northeast-2.amazonaws.com/ap-northeast-2_TestPool"


@pytest.fixture
def configured_cli(monkeypatch, tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("Configuration validation only")
    for name in ("SKY_PRIVATE_OPERATOR_JSON", "SKY_ALB_TRUSTS_JSON"):
        monkeypatch.delenv(name, raising=False)
    for key, value in {
        "SKY_DATABASE_HOST": "db.example",
        "SKY_DATABASE_NAME": "sky",
        "SKY_DATABASE_SECRET_ARN": "arn:aws:secretsmanager:ap-northeast-2:111111111111:secret:test",
        "SKY_AWS_REGION": "ap-northeast-2",
        "SKY_DATABASE_SSLROOTCERT": str(ca),
        "SKY_STATE_WORKSPACE": "security_test",
        "SKY_COGNITO_AUTH_JSON": json.dumps(
            {"version": 1, "issuer": ISSUER, "client_id": "client123", "required_scopes": ["sky/deploy"]}
        ),
        "SKY_MEMBERSHIPS_JSON": json.dumps(
            {
                "version": 1,
                "members": [
                    {
                        "issuer": ISSUER,
                        "subject": "admin-sub",
                        "user_id": "user1",
                        "organization_id": "org1",
                        "role": "admin",
                        "enabled": True,
                    }
                ],
            }
        ),
    }.items():
        monkeypatch.setenv(key, value)


def arguments(action="status"):
    args = ["security-hold", action, "--job-id", ID, "--user-id", "user1", "--organization-id", "org1"]
    if action == "place":
        args += ["--incident-id", "INC-1", "--reason", "suspected_compromise", "--confirm-hold"]
    return args


@pytest.mark.parametrize("action", ["place", "status", "observe"])
def test_configuration_check_does_not_create_clients_or_connect(configured_cli, action, capsys):
    with (
        patch("boto3.client", side_effect=AssertionError("Cloud")),
        patch("interfaces.security_hold.RotatingDatabaseConnection", side_effect=AssertionError("Database")),
    ):
        main(arguments(action) + ["--check-config"])
    assert "no AWS/DB calls" in capsys.readouterr().out


@pytest.mark.parametrize(
    "change",
    ["no-confirm", "status-mutation", "job", "user", "role", "mixed-identity", "disabled", "ambiguous"],
)
def test_invalid_or_unauthorized_cli_fails_before_provider(configured_cli, monkeypatch, change):
    args = arguments("place")
    if change == "no-confirm":
        args.remove("--confirm-hold")
    elif change == "status-mutation":
        args[1] = "status"
    elif change == "job":
        args[args.index("--job-id") + 1] = "not-a-job"
    elif change == "user":
        args[args.index("--user-id") + 1] = "unregistered"
    elif change == "mixed-identity":
        monkeypatch.setenv("SKY_ALB_TRUSTS_JSON", "{}")
    else:
        doc = json.loads(os.environ["SKY_MEMBERSHIPS_JSON"])
        if change == "role":
            doc["members"][0]["role"] = "deployer"
        elif change == "disabled":
            doc["members"][0]["enabled"] = False
        else:
            doc["members"].append({**doc["members"][0], "subject": "second-sub"})
        monkeypatch.setenv("SKY_MEMBERSHIPS_JSON", json.dumps(doc))
    with (
        patch("interfaces.security_hold.RotatingDatabaseConnection", side_effect=AssertionError("Database")),
        pytest.raises(SystemExit) as result,
    ):
        main(args + ["--check-config"])
    assert result.value.code == 2


def test_status_is_sanitized_and_does_not_label_missing_record_safe():
    records = Records()
    service = SecurityHold(records)
    result = service.status(principal(role=Role.ADMIN), ID)
    assert result["status"] == "not_recorded" and result["hold"] is None
    records.job["security_hold"] = {"password": "must-not-disclose"}
    result = service.status(principal(role=Role.ADMIN), ID)
    assert result["status"] == "held" and result["record_valid"] is False
    assert "must-not-disclose" not in json.dumps(result)
    assert records.save_calls == 0


def test_status_requires_current_admin_and_same_organization():
    records = Records()
    with pytest.raises(PermissionError):
        SecurityHold(records).status(principal(), ID)
    with pytest.raises(FileNotFoundError):
        SecurityHold(records).status(principal(org="other", role=Role.ADMIN), ID)


def test_membership_change_before_write_is_not_ignored(configured_cli):
    records = Records()
    admin = principal(role=Role.ADMIN)
    with (
        patch("interfaces.security_hold.operator", side_effect=[admin, replace(admin, role=Role.VIEWER)]),
        patch("interfaces.security_hold.RotatingDatabaseConnection", return_value=Mock()),
        patch("interfaces.security_hold.check_database_ready"),
        patch("interfaces.security_hold.PostgresDeploymentRecordStore", return_value=records),
        pytest.raises(SystemExit) as result,
    ):
        main(arguments("place"))
    assert result.value.code == 1 and records.save_calls == 0


def test_runtime_errors_do_not_print_credentials(configured_cli, capsys):
    with (
        patch(
            "interfaces.security_hold.RotatingDatabaseConnection", side_effect=OSError("must-not-disclose")
        ),
        pytest.raises(SystemExit) as result,
    ):
        main(arguments("place"))
    assert result.value.code == 1
    assert "must-not-disclose" not in capsys.readouterr().err
    assert "must-not-disclose" not in str(result.value)


def test_service_entrypoint_routes_hold_without_legacy_state():
    with (
        patch("sys.argv", ["sky-service", *arguments()]),
        patch("interfaces.b_runtime.main") as run,
        patch("interfaces.service.require_service_state", side_effect=AssertionError("Legacy state")),
    ):
        service_main()
    run.assert_called_once_with(arguments())


def test_alb_operator_configuration_remains_supported_without_token_or_cloud(
    configured_cli, monkeypatch, capsys
):
    monkeypatch.delenv("SKY_COGNITO_AUTH_JSON")
    monkeypatch.setenv(
        "SKY_ALB_TRUSTS_JSON",
        json.dumps(
            {
                "version": 1,
                "trusts": [
                    {
                        "signer_arn": "arn:aws:elasticloadbalancing:ap-northeast-2:111111111111:loadbalancer/app/sky/0123456789abcdef",
                        "issuer": ISSUER,
                        "client_id": "client123",
                        "login_source": "corporate_sso",
                    }
                ],
            }
        ),
    )
    with patch("interfaces.security_hold.RotatingDatabaseConnection", side_effect=AssertionError("Database")):
        main(arguments() + ["--auth-mode", "alb", "--check-config"])
    assert "no AWS/DB calls" in capsys.readouterr().out


def test_observe_uses_fixed_probe_without_mutation_or_external_receipts(
    configured_cli, capsys, operating_review_setup
):
    from datetime import UTC, datetime

    records, _, _ = operating_review_setup
    SecurityHold(records).place(
        principal(role=Role.ADMIN),
        ID,
        incident_id="INC-1",
        reason="suspected_compromise",
        now=datetime.now(UTC).isoformat(),
    )
    previous = json.loads(json.dumps(records.job))
    with (
        patch("interfaces.security_hold.RotatingDatabaseConnection", return_value=Mock()),
        patch("interfaces.security_hold.check_database_ready"),
        patch("interfaces.security_hold.PostgresDeploymentRecordStore", return_value=records),
        patch(
            "interfaces.security_hold.check_deployment",
            side_effect=lambda job: {
                "healthy": True,
                "checked_at": datetime.now(UTC).isoformat(),
                "reason": "HTTP checked",
            },
        ) as probe,
    ):
        main(arguments("observe"))
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "held" and report["health_observation"]["healthy"] is True
    assert report["quarantine_performed"] is False and report["credentials_revoked"] is False
    assert records.job == previous
    probe.assert_called_once()
    assert (
        records.health[-1]["deployment_binding"]["security_review_boundary"]
        == previous["security_review_boundary"]
    )


def release_arguments(revision=1, boundary="a" * 32):
    return arguments("release-false-positive") + [
        "--incident-id",
        "INC-1",
        "--review-ref",
        "REVIEW-1",
        "--expected-revision",
        str(revision),
        "--expected-boundary",
        boundary,
        "--confirm-false-positive",
    ]


def test_false_positive_check_config_requires_explicit_review_without_clients(configured_cli, capsys):
    with patch("interfaces.security_hold.RotatingDatabaseConnection", side_effect=AssertionError("DB")):
        main(release_arguments() + ["--check-config"])
    assert "no AWS/DB calls" in capsys.readouterr().out


@pytest.mark.parametrize(
    "option",
    [
        "--incident-id",
        "--review-ref",
        "--expected-revision",
        "--expected-boundary",
        "--confirm-false-positive",
    ],
)
def test_false_positive_release_cannot_omit_review_confirmation(configured_cli, option):
    args = release_arguments()
    index = args.index(option)
    del args[index : index + (1 if option == "--confirm-false-positive" else 2)]
    with (
        patch("interfaces.security_hold.RotatingDatabaseConnection", side_effect=AssertionError("DB")),
        pytest.raises(SystemExit) as result,
    ):
        main(args + ["--check-config"])
    assert result.value.code == 2


@pytest.mark.parametrize("action", ["status", "observe", "place"])
def test_release_options_cannot_be_smuggled_into_other_actions(configured_cli, action):
    with (
        patch("interfaces.security_hold.RotatingDatabaseConnection", side_effect=AssertionError("DB")),
        pytest.raises(SystemExit) as result,
    ):
        main(arguments(action) + ["--review-ref", "REVIEW-1", "--confirm-false-positive", "--check-config"])
    assert result.value.code == 2
