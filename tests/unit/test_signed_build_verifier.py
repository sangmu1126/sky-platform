"""Expected request, live manifest and independently pinned signing key must agree."""

import json
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from adapters.aws.build_image import SignedEcrBuildVerifier
from tests.unit.test_kms_build_signature import NOW, signed
from tests.unit.test_kms_build_signature import context as context  # noqa: PLC0414


def setup(c):
    result = json.loads((c.root / "published-proof/result.json").read_bytes())
    manifest = (c.root / "published-proof/manifest.json").read_text()
    client = Mock()
    client.batch_get_image.return_value = {
        "images": [{"imageId": {"imageDigest": result["image_digest"]}, "imageManifest": manifest}]
    }
    objects = Mock()
    objects.read.return_value = signed(c)
    key = Mock()
    key.observe.return_value = {"key_liveness_checked": True, "key_arn": c.identity.key_arn}
    settings = SimpleNamespace(account_id=c.identity.account_id, region=c.identity.region)
    verifier = SignedEcrBuildVerifier(
        settings, objects=objects, identity=c.identity, key_observer=key, client=client, clock=lambda: NOW
    )
    return verifier, result, objects, client, key


def test_signed_input_binding_is_required_in_addition_to_current_image(context):
    verifier, result, objects, _, _ = setup(context)
    proof = verifier.verify(context.request, result)
    assert proof["signature_verified"] and proof["key_liveness_checked"]
    assert proof["expected_input_binding_matched"] and not proof["image_safety_verified"]
    objects.read.assert_called_once_with(f"builds/{context.request['build_id']}/signature.json")


@pytest.mark.parametrize("change", ["source", "workflow", "signature", "manifest", "key-disabled"])
def test_valid_image_alone_cannot_admit_untrusted_provenance(context, change):
    verifier, result, objects, client, key = setup(context)
    request = deepcopy(context.request)
    if change == "source":
        request["source_digest"] = "f" * 64
    elif change == "workflow":
        request["workflow_sha"] = "f" * 40
    elif change == "signature":
        objects.read.return_value["payload"]["statement"]["repository"] = "foreign/builder"
    elif change == "manifest":
        client.batch_get_image.return_value["images"][0]["imageManifest"] += " "
    else:
        key.observe.side_effect = ValueError("Key is disabled")
    with pytest.raises(ValueError):
        verifier.verify(request, result)


def test_hosted_verifier_requires_inspection_in_the_signed_statement(context):
    verifier, result, _objects, _, _ = setup(context)
    verifier.require_inspection = True
    with pytest.raises(ValueError, match="missing signed security"):
        verifier.verify(context.request, result)


def test_signed_inspection_cannot_be_detached_from_the_image(context):
    from uuid import uuid4

    from tests.unit.test_image_security import report

    inspected = report()
    inspected["archive_sha256"] = context.statement["archive_digest"]
    materials = dict.fromkeys(("base_archive_sha256", "context_sha256", "profile_sha256"), "a" * 64)
    materials.update(build_vm_job=str(uuid4()), scanner_vm_job=str(uuid4()))
    context.statement["security"] = {"report": inspected, "materials": materials}
    verifier, result, objects, _, _ = setup(context)
    verifier.require_inspection = True
    assert verifier.verify(context.request, result)["signature_verified"]
    objects.read.return_value["payload"]["statement"]["security"]["report"]["secret_count"] = 1
    with pytest.raises(ValueError):
        verifier.verify(context.request, result)
