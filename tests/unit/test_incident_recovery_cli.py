from dataclasses import asdict, replace
from unittest.mock import patch

import pytest

from domain.incident_recovery import RecoveryRuntimeRegistration
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
        ("approve-recovery", None),
        ("execute-recovery", None),
        ("approve-recovery", "no-confirm"),
        ("execute-recovery", "no-confirm"),
        ("approve-recovery", "mixed-confirm"),
        ("execute-recovery", "approval-reference"),
        ("approve-recovery", "runtime-scope"),
        ("approve-recovery", "other-mutation"),
    ],
)
def test_recovery_preflight_is_disjoint_and_has_no_provider_calls(
    configured_cli, registration, context, action, change, capsys
):
    path, _ = registration
    service, _, _ = combined(context)
    image = replace(service.image_registration, organization_id="org1")
    image_path = path.parent / "image.json"
    image_path.write_bytes(canonical({"version": 1, **asdict(image)}))
    account = image.account_id
    region = image.region
    runtime = RecoveryRuntimeRegistration(
        "org1",
        image.application_id,
        image.job_id,
        image.incident_id,
        image.boundary_id,
        "f" * 32,
        account,
        region,
        f"arn:aws:ecs:{region}:{account}:cluster/sky-recovery-test",
        "vpc-" + "a" * 17,
        ("subnet-" + "b" * 17,),
        "sg-" + "c" * 17,
        f"arn:aws:iam::{account}:role/sky-recovery-execution",
        "AROA" + "A" * 17,
        f"arn:aws:iam::{account}:role/sky-recovery-task",
        "AROA" + "B" * 17,
        f"app.test.{region}.rds.amazonaws.com",
    )
    runtime_path = path.parent / "runtime.json"
    runtime_path.write_bytes(canonical({"version": 1, "registration": runtime.document()}))
    args = cli(path)
    args[1] = action
    args += [
        "--recovery-image-config",
        str(image_path),
        "--recovery-runtime-config",
        str(runtime_path),
        "--recovery-id",
        "f" * 32,
    ]
    if action == "approve-recovery":
        args += [
            "--artifact-review-id",
            "c" * 32,
            "--recovery-approval-ref",
            "RECOVERY-1",
            "--confirm-recovery-approval",
        ]
    else:
        args += ["--confirm-recovery-execution"]
    if change == "no-confirm":
        args.remove(
            "--confirm-recovery-approval" if action == "approve-recovery" else "--confirm-recovery-execution"
        )
    if change == "mixed-confirm":
        args += ["--confirm-recovery-execution"]
    if change == "approval-reference":
        args += ["--recovery-approval-ref", "OTHER"]
    if change == "other-mutation":
        args += ["--confirm-database-restriction"]
    if change == "runtime-scope":
        runtime_path.write_bytes(
            canonical({"version": 1, "registration": {**runtime.document(), "organization_id": "other"}})
        )
    # Workload pool/Secret loaders are independently tested. This isolates the
    # new CLI's identity/image/runtime registration and confirmation boundary.
    with (
        patch(
            "interfaces.incident_recovery.load_readiness_configuration",
            return_value=(object(), None, object()),
        ),
        patch("boto3.Session", side_effect=AssertionError("AWS")),
        patch("interfaces.incident_recovery.RotatingDatabaseConnection", side_effect=AssertionError("DB")),
    ):
        if change is None:
            main(args + ["--check-config"])
            assert "no AWS/DB calls" in capsys.readouterr().out
        else:
            with pytest.raises(SystemExit) as error:
                main(args + ["--check-config"])
            assert error.value.code == 2
