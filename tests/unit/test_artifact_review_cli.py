from dataclasses import asdict, replace
from unittest.mock import patch

import pytest

from interfaces.b_runtime import main
from ports.remote_builds import canonical
from tests.unit.test_build_approval_cli import cli
from tests.unit.test_build_approval_cli import registration as registration  # noqa: PLC0414
from tests.unit.test_incident_build_image import combined
from tests.unit.test_kms_build_signature import context as context  # noqa: PLC0414
from tests.unit.test_security_hold_cli import configured_cli as configured_cli  # noqa: PLC0414


@pytest.mark.parametrize(
    "action,change",
    [
        ("approve", None),
        ("check", None),
        ("readiness", None),
        ("readiness", "approve-confirm"),
        ("readiness", "operation-id"),
        ("readiness", "database-confirm"),
        ("revoke", None),
        ("approve", "missing-confirm"),
        ("approve", "missing-ref"),
        ("approve", "bad-ttl"),
        ("approve", "false-positive"),
        ("check", "approve-confirm"),
        ("check", "reference"),
        ("revoke", "missing-confirm"),
        ("revoke", "cloud-config"),
    ],
)
def test_explicit_disjoint_review_preflight(configured_cli, registration, context, action, change, capsys):
    path, _ = registration
    service, _, _ = combined(context)
    image = replace(service.image_registration, organization_id="org1")
    image_path = path.parent / "image.json"
    image_path.write_bytes(canonical({"version": 1, **asdict(image)}))
    args = cli(path)
    args[1] = "check-recovery-readiness" if action == "readiness" else f"{action}-artifact-review"
    args += ["--artifact-review-id", "c" * 32]
    if action == "revoke":
        index = args.index("--build-approval-config")
        del args[index : index + 2]
        args += ["--artifact-review-ref", "REVOKE-1", "--confirm-artifact-review-revocation"]
    else:
        args += ["--recovery-image-config", str(image_path)]
        if action == "approve":
            args += ["--artifact-review-ref", "REVIEW-1", "--confirm-artifact-review"]
    if change == "missing-confirm":
        args.remove(
            "--confirm-artifact-review" if action == "approve" else "--confirm-artifact-review-revocation"
        )
    elif change == "missing-ref":
        index = args.index("--artifact-review-ref")
        del args[index : index + 2]
    elif change == "bad-ttl":
        args += ["--artifact-review-seconds", "0"]
    elif change == "false-positive":
        args += ["--confirm-false-positive", "--review-ref", "FALSE-1"]
    elif change == "approve-confirm":
        args += ["--confirm-artifact-review"]
    elif change == "reference":
        args += ["--artifact-review-ref", "REVIEW-2"]
    elif change == "operation-id":
        args += ["--expected-operation-id", "d" * 32]
    elif change == "database-confirm":
        args += ["--confirm-database-restriction"]
    elif change == "cloud-config":
        args += ["--build-approval-config", str(path)]
    with (
        patch("boto3.Session", side_effect=AssertionError("Cloud")),
        patch("interfaces.security_hold.RotatingDatabaseConnection", side_effect=AssertionError("Database")),
    ):
        if change is None:
            main(args + ["--check-config"])
            assert "no AWS/DB calls" in capsys.readouterr().out
        else:
            with pytest.raises(SystemExit) as exc:
                main(args + ["--check-config"])
            assert exc.value.code == 2
