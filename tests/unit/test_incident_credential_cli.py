from unittest.mock import patch

import pytest

from interfaces.b_runtime import main
from tests.unit.test_incident_database_cli import command

pytest_plugins = ["tests.unit.test_security_hold_cli", "tests.unit.test_shared_database_worker_cli"]


def arguments(path):
    result = command(path, "inspect-database")
    result[1] = "prepare-credentials"
    return result + ["--confirm-credential-preparation"]


def test_configuration_validation_does_not_access_aws_or_database(configured_cli, configuration, capsys):
    with (
        patch("interfaces.security_hold.AwsSharedDatabaseAllocator", side_effect=AssertionError("AWS")),
        patch("interfaces.security_hold.RotatingDatabaseConnection", side_effect=AssertionError("SQL")),
    ):
        main(arguments(configuration[0]) + ["--check-config"])
    assert "no AWS/DB calls" in capsys.readouterr().out


@pytest.mark.parametrize("change", ["confirmation", "missing-operation", "mutation-mix", "wrong-action"])
def test_preparation_needs_exact_confirmation_and_restriction_identity(configured_cli, configuration, change):
    args = arguments(configuration[0])
    if change == "confirmation":
        args.remove("--confirm-credential-preparation")
    elif change == "missing-operation":
        index = args.index("--expected-operation-id")
        del args[index : index + 2]
    elif change == "mutation-mix":
        args += ["--confirm-database-restriction"]
    else:
        args[1] = "inspect-database"
    with (
        patch("interfaces.security_hold.RotatingDatabaseConnection", side_effect=AssertionError("SQL")),
        pytest.raises(SystemExit) as error,
    ):
        main(args + ["--check-config"])
    assert error.value.code == 2


def test_read_only_inspection_config_requires_no_confirmation_or_provider(
    configured_cli, configuration, capsys
):
    args = arguments(configuration[0])
    args[1] = "inspect-credentials"
    args.remove("--confirm-credential-preparation")
    with (
        patch("interfaces.security_hold.AwsSharedDatabaseAllocator", side_effect=AssertionError("AWS")),
        patch("interfaces.security_hold.RotatingDatabaseConnection", side_effect=AssertionError("SQL")),
    ):
        main(args + ["--check-config"])
    assert "no AWS/DB calls" in capsys.readouterr().out
    with pytest.raises(SystemExit) as error:
        main(args + ["--confirm-credential-preparation", "--check-config"])
    assert error.value.code == 2
