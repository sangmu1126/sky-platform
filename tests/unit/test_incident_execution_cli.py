from unittest.mock import patch

import pytest

from interfaces.b_runtime import main
from tests.unit.test_security_hold_cli import arguments
from tests.unit.test_security_hold_cli import configured_cli as configured_cli  # noqa: PLC0414


@pytest.mark.parametrize(
    "action,invalid",
    [
        ("fence-execution", None),
        ("inspect-execution-fence", None),
        ("fence-execution", "missing-confirm"),
        ("inspect-execution-fence", "confirm"),
        ("inspect-execution-fence", "other-mutation"),
        ("inspect-execution-fence", "artifact"),
    ],
)
def test_execution_barrier_preflight_never_connects(configured_cli, action, invalid, capsys):
    args = arguments(action) + [
        "--incident-id",
        "INC-1",
        "--expected-boundary",
        "b" * 32,
        "--expected-revision",
        "2",
        "--check-config",
    ]
    if action == "fence-execution" and invalid != "missing-confirm" or invalid == "confirm":
        args += ["--confirm-execution-fence"]
    if invalid == "other-mutation":
        args += ["--confirm-database-restriction"]
    if invalid == "artifact":
        args += ["--artifact-review-id", "c" * 32]
    with (
        patch("boto3.Session", side_effect=AssertionError("AWS")),
        patch("interfaces.incident_execution.RotatingDatabaseConnection", side_effect=AssertionError("DB")),
    ):
        if invalid is None:
            main(args)
            assert "no AWS/DB calls" in capsys.readouterr().out
        else:
            with pytest.raises(SystemExit) as error:
                main(args)
            assert error.value.code == 2
