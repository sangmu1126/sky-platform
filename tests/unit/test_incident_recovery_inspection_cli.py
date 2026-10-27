from unittest.mock import patch

import pytest

from interfaces.b_runtime import main
from tests.unit.test_security_hold_cli import arguments
from tests.unit.test_security_hold_cli import configured_cli as configured_cli  # noqa: PLC0414


def args():
    return arguments("inspect-recovery") + [
        "--incident-id",
        "INC-1",
        "--expected-boundary",
        "a" * 32,
        "--expected-revision",
        "1",
        "--recovery-id",
        "f" * 32,
        "--check-config",
    ]


@pytest.mark.parametrize(
    "extra",
    [
        [],
        ["--confirm-recovery-execution"],
        ["--recovery-seconds", "0"],
        ["--pool-config", "unknown"],
        ["--recovery-runtime-config", "unknown"],
        ["--confirm-hold"],
    ],
)
def test_configuration_is_read_only_and_needs_no_workload_registration(configured_cli, extra, capsys):
    with (
        patch("boto3.client", side_effect=AssertionError("AWS")),
        patch(
            "interfaces.incident_recovery_inspection.RotatingDatabaseConnection",
            side_effect=AssertionError("DB"),
        ),
    ):
        if extra:
            with pytest.raises(SystemExit) as e:
                main(args() + extra)
            assert e.value.code == 2
        else:
            main(args())
            assert "no AWS/DB calls" in capsys.readouterr().out


def test_unregistered_admin_cannot_inspect_even_configuration(configured_cli):
    values = args()
    values[values.index("--user-id") + 1] = "foreign"
    with pytest.raises(SystemExit) as e:
        main(values)
    assert e.value.code == 2


def test_runtime_database_errors_are_sanitized_without_printing_success(configured_cli, capsys):
    values = args()
    values.remove("--check-config")
    with (
        patch(
            "interfaces.incident_recovery_inspection.RotatingDatabaseConnection",
            side_effect=OSError("credential-value-must-not-leak"),
        ),
        pytest.raises(SystemExit) as e,
    ):
        main(values)
    output = capsys.readouterr()
    assert e.value.code == 1 and not output.out
    assert "credential-value-must-not-leak" not in output.err
    assert "no activation, retry or state change" in output.err
