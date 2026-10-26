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


@pytest.mark.parametrize("change", [None, "missing-image", "missing-build", "run", "digest", "mutation"])
def test_combined_preflight_pins_and_disjoint_options(configured_cli, registration, context, change, capsys):
    path, _ = registration
    service, _, _ = combined(context)
    r = replace(service.image_registration, organization_id="org1")
    if change == "run":
        r = replace(r, build_reference=r.build_reference[:-3] + "124")
    elif change == "digest":
        r = replace(r, image=r.image.split("@")[0] + "@sha256:" + "f" * 64)
    image_path = path.parent / "image.json"
    image_path.write_bytes(canonical({"version": 1, **asdict(r)}))
    args = cli(path)
    args[1] = "inspect-build-image"
    if change != "missing-image":
        args += ["--recovery-image-config", str(image_path)]
    if change == "missing-build":
        index = args.index("--build-approval-config")
        del args[index : index + 2]
    elif change == "mutation":
        args += ["--confirm-false-positive", "--review-ref", "review"]
    with (
        patch("boto3.Session", side_effect=AssertionError("No cloud calls during preflight")),
        patch("interfaces.security_hold.RotatingDatabaseConnection", side_effect=AssertionError("Database")),
    ):
        if change is None:
            main(args + ["--check-config"])
            assert "no AWS/DB calls" in capsys.readouterr().out
        else:
            with pytest.raises(SystemExit) as exc:
                main(args + ["--check-config"])
            assert exc.value.code == 2
