import hashlib
import json
from copy import deepcopy
from dataclasses import asdict, replace
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from adapters.aws.recovery_image import AwsRecoveryImageInspector
from application.recovery_image_inspection import RecoveryImageInspection
from domain.recovery_image import RecoveryImageRegistration
from interfaces.b_runtime import main
from interfaces.recovery_image_registration import load_recovery_image_registration
from ports.state import RecordConflict
from tests.unit.test_incident_runtime_inspection import application
from tests.unit.test_operating_review import ID, NOW
from tests.unit.test_security_hold_cli import arguments

pytest_plugins = ["tests.unit.test_operating_review", "tests.unit.test_security_hold_cli"]
CONFIG = "sha256:" + "c" * 64
MANIFEST = json.dumps(
    {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": CONFIG, "size": 2},
        "layers": [],
    }
)
DIGEST = "sha256:" + hashlib.sha256(MANIFEST.encode()).hexdigest()


def registration(**changes):
    fields = dict(  # noqa: C408 -- keyword pins keep test overrides explicit
        organization_id="org1",
        application_id="app1",
        job_id=ID,
        incident_id="INC-1",
        boundary_id="b" * 32,
        account_id="111111111111",
        region="ap-northeast-2",
        image=f"111111111111.dkr.ecr.ap-northeast-2.amazonaws.com/recovery@{DIGEST}",
        config_digest=CONFIG,
        source_revision="a" * 40,
        source_digest="sha256:" + "b" * 64,
        build_reference="https://github.com/sangmu1126/sky-platform/actions/runs/123",
    )
    return RecoveryImageRegistration(**(fields | changes))


def native(r=None):
    r = r or registration()
    clients = {name: Mock(spec=["meta", "batch_get_image", "get_caller_identity"]) for name in ("ecr", "sts")}
    for c in clients.values():
        c.meta = SimpleNamespace(region_name=r.region)
    clients["sts"].get_caller_identity.return_value = {"Account": r.account_id}
    image = {
        "registryId": r.account_id,
        "repositoryName": r.repository,
        "imageId": {"imageDigest": r.manifest_digest},
        "imageManifest": MANIFEST,
        "imageManifestMediaType": "application/vnd.oci.image.manifest.v1+json",
    }
    clients["ecr"].batch_get_image.return_value = {"images": [image], "failures": []}
    adapter = AwsRecoveryImageInspector(
        session=Mock(client=lambda name, **kw: clients[name]), clock=lambda: datetime.fromisoformat(NOW)
    )
    return adapter, clients, image


def test_exact_bytes_are_verified_without_claiming_source_or_safety():
    r = registration()
    adapter, clients, _ = native(r)
    result = adapter.inspect(r, guard=lambda: None)
    assert result["manifest_bytes_verified"] is True
    assert result["config_descriptor_verified"] is True
    for k in ("source_provenance_verified", "image_safety_verified", "recovery_authorized", "state_changed"):
        assert result[k] is False
    assert clients["ecr"].batch_get_image.call_args.kwargs == {
        "registryId": r.account_id,
        "repositoryName": r.repository,
        "imageIds": [{"imageDigest": r.manifest_digest}],
    }


@pytest.mark.parametrize(
    "change",
    ["account", "region", "repository", "digest", "bytes", "config", "failure", "duplicate", "media"],
)
def test_native_foreign_ambiguous_or_tampered_images_fail_closed(change):
    r = registration()
    adapter, clients, image = native(r)
    if change == "account":
        clients["sts"].get_caller_identity.return_value = {"Account": "222222222222"}
    elif change == "region":
        clients["ecr"].meta.region_name = "us-east-1"
    elif change == "repository":
        image["repositoryName"] = "foreign"
    elif change == "digest":
        image["imageId"]["imageDigest"] = CONFIG
    elif change == "bytes":
        image["imageManifest"] += " "
    elif change == "config":
        r = replace(r, config_digest="sha256:" + "d" * 64)
    elif change == "failure":
        clients["ecr"].batch_get_image.return_value["failures"] = [{"failureCode": "ImageNotFound"}]
    elif change == "duplicate":
        clients["ecr"].batch_get_image.return_value["images"] *= 2
    else:
        image["imageManifestMediaType"] = "foreign"
    with pytest.raises(ValueError):
        adapter.inspect(r, guard=lambda: None)


@pytest.mark.parametrize(
    "manifest",
    [
        '{"schemaVersion":2,"schemaVersion":2}',
        '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}',
    ],
)
def test_indexes_and_duplicate_fields_are_not_silently_accepted(manifest):
    r = registration()
    d = "sha256:" + hashlib.sha256(manifest.encode()).hexdigest()
    r = replace(r, image=r.image.split("@")[0] + "@" + d)
    adapter, _, image = native(r)
    image["imageManifest"] = manifest
    with pytest.raises(ValueError):
        adapter.inspect(r, guard=lambda: None)


@pytest.mark.parametrize(
    "field,value",
    [
        ("image", "111111111111.dkr.ecr.ap-northeast-2.amazonaws.com/recovery:latest"),
        ("image", "222222222222.dkr.ecr.ap-northeast-2.amazonaws.com/recovery@" + DIGEST),
        ("source_revision", "main"),
        ("source_digest", "unknown"),
        ("config_digest", "latest"),
        ("build_reference", "https://evil.test/run/123"),
        ("job_id", "foreign"),
    ],
)
def test_registration_requires_exact_operator_pins(field, value):
    with pytest.raises(ValueError):
        registration(**{field: value})


def app(fixture):
    records, actor, _, args, _ = application(fixture)
    r = registration(
        organization_id=actor.organization_id,
        application_id=records.job["application_id"],
        incident_id=args["incident_id"],
        boundary_id=args["expected_boundary"],
    )
    adapter, _, _ = native(r)
    inspector = Mock()
    inspector.inspect.side_effect = lambda supplied, **kw: adapter.inspect(supplied, **kw)
    service = RecoveryImageInspection(records, r, inspector, clock=lambda: NOW, revalidate=lambda: actor)
    return records, actor, service, args, inspector


def test_incident_image_inspection_preserves_metadata_hold_and_credential_phase(operating_review_setup):
    records, actor, service, args, _ = app(operating_review_setup)
    before, saves = deepcopy(records.job), records.save_calls
    receipt = service.inspect(actor, ID, **args)
    assert receipt["operator_declared_source"]["revision"] == "a" * 40
    assert not receipt["source_provenance_verified"] and not receipt["recovery_authorized"]
    assert records.job == before and records.save_calls == saves


@pytest.mark.parametrize(
    "change", ["revision", "organization", "application", "incident", "boundary", "revoked"]
)
def test_stale_or_foreign_review_has_no_native_calls(operating_review_setup, change):
    _, actor, service, args, inspector = app(operating_review_setup)
    if change == "revision":
        args["expected_revision"] += 1
    elif change == "revoked":
        service.scope.revalidate = lambda: None
    else:
        key = {
            "organization": "organization_id",
            "application": "application_id",
            "incident": "incident_id",
            "boundary": "boundary_id",
        }[change]
        service.registration = replace(service.registration, **{key: "f" * 32})
    with pytest.raises((ValueError, PermissionError, RecordConflict)):
        service.inspect(actor, ID, **args)
    inspector.inspect.assert_not_called()


def test_concurrent_change_after_native_read_is_not_returned_as_success(operating_review_setup):
    records, actor, service, args, inspector = app(operating_review_setup)
    original = inspector.inspect.side_effect

    def changed(*a, **kw):
        value = original(*a, **kw)
        records.job["unexpected"] = True
        return value

    inspector.inspect.side_effect = changed
    with pytest.raises(RecordConflict):
        service.inspect(actor, ID, **args)


@pytest.mark.parametrize(
    "change", ["source_provenance_verified", "recovery_authorized", "state_changed", "observed_at"]
)
def test_overstated_or_stale_native_receipt_is_rejected(operating_review_setup, change):
    _, actor, service, args, inspector = app(operating_review_setup)
    original = inspector.inspect.side_effect
    inspector.inspect.side_effect = lambda *a, **kw: (
        original(*a, **kw) | {change: "2000-01-01T00:00:00+00:00" if change == "observed_at" else True}
    )
    with pytest.raises(OSError):
        service.inspect(actor, ID, **args)


def test_trusted_registration_loader_rejects_unknown_duplicate_or_oversized_data(tmp_path):
    path = tmp_path / "review.json"
    data = {"version": 1, **asdict(registration())}
    path.write_text(json.dumps(data))
    assert load_recovery_image_registration(path) == registration()
    for raw in (
        json.dumps(data | {"extra": True}),
        json.dumps(data | {"version": True}),
        '{"version":1,' + json.dumps(data)[1:],
        " " * 16385,
    ):
        path.write_text(raw)
        with pytest.raises(ValueError):
            load_recovery_image_registration(path)


def test_cli_config_check_has_no_native_or_state_calls(configured_cli, tmp_path, capsys):
    path = tmp_path / "review.json"
    path.write_text(json.dumps({"version": 1, **asdict(registration())}))
    args = arguments("inspect-recovery-image") + [
        "--incident-id",
        "INC-1",
        "--expected-boundary",
        "b" * 32,
        "--expected-revision",
        "1",
        "--recovery-image-config",
        str(path),
        "--check-config",
    ]
    with (
        patch("interfaces.security_hold.RotatingDatabaseConnection", side_effect=AssertionError("db")),
        patch("boto3.Session", side_effect=AssertionError("aws")),
    ):
        main(args)
    assert "no AWS/DB calls" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        main(args + ["--confirm-credential-preparation"])
