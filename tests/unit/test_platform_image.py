import hashlib
import json

import pytest

from domain.platform_image import verify_platform_image


def raw(value):
    return json.dumps(value, separators=(",", ":")).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def case(*, duplicate=False):
    config = raw(
        {
            "os": "linux",
            "architecture": "arm64",
            "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "a" * 64]},
        }
    )
    manifest = raw(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": digest(config),
                "size": len(config),
            },
        }
    )
    descriptor = {
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "platform": {"os": "linux", "architecture": "arm64"},
        "digest": digest(manifest),
        "size": len(manifest),
    }
    index = raw(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [descriptor] * (2 if duplicate else 1),
        }
    )
    return (
        index,
        manifest,
        config,
        {
            "expected_index_digest": digest(index),
            "platform_os": "linux",
            "architecture": "arm64",
            "observed_rootfs": ("sha256:" + "a" * 64,),
        },
    )


def test_image_definition_chain_does_not_claim_running_host_integrity_or_execution():
    index, manifest, config, kwargs = case()
    proof = verify_platform_image(index, manifest, config, **kwargs)
    assert (
        proof["platform_manifest_digest"] == digest(manifest) and not proof["running_host_integrity_attested"]
    )
    assert not proof["execution_authorized"]


@pytest.mark.parametrize("part", [0, 1, 2])
def test_content_mutation_is_rejected_even_if_names_and_tags_match(part):
    values = list(case())
    values[part] += b" "
    with pytest.raises(ValueError):
        verify_platform_image(*values[:3], **values[3])


def test_ambiguous_or_wrong_architecture_cannot_claim_same_executable():
    index, manifest, config, kwargs = case(duplicate=True)
    with pytest.raises(ValueError, match="Exactly one"):
        verify_platform_image(index, manifest, config, **kwargs)
    index, manifest, config, kwargs = case()
    kwargs["architecture"] = "amd64"
    with pytest.raises(ValueError):
        verify_platform_image(index, manifest, config, **kwargs)


def test_changed_layer_order_or_content_is_not_the_same_image_definition():
    index, manifest, config, kwargs = case()
    kwargs["observed_rootfs"] = ("sha256:" + "b" * 64,)
    with pytest.raises(ValueError, match="rootfs"):
        verify_platform_image(index, manifest, config, **kwargs)


@pytest.mark.parametrize("platform", [None, [], "linux/arm64"])
def test_malformed_platform_descriptor_cannot_bypass_qualified_platform(platform):
    index, manifest, config, kwargs = case()
    value = json.loads(index)
    value["manifests"][0]["platform"] = platform
    index = raw(value)
    kwargs["expected_index_digest"] = digest(index)
    with pytest.raises(ValueError, match="descriptors"):
        verify_platform_image(index, manifest, config, **kwargs)


def test_duplicate_json_field_rejected_even_when_raw_digest_matches():
    index, manifest, config, kwargs = case()
    index = index.replace(b'"schemaVersion":2', b'"schemaVersion":2,"schemaVersion":2')
    kwargs["expected_index_digest"] = digest(index)
    with pytest.raises(ValueError, match="Ambiguous"):
        verify_platform_image(index, manifest, config, **kwargs)
