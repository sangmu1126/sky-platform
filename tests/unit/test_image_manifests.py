"""Raw registry manifest and built config digest must agree."""

import hashlib
import json

import pytest

from ports.image_manifests import MANIFEST_TYPES, verify_image_manifest

IMAGE_ID = "sha256:" + "a" * 64


def manifest(**changes):
    return json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": MANIFEST_TYPES[0],
            "config": {"digest": IMAGE_ID},
            "layers": [],
            **changes,
        }
    ).encode()


def verify(payload, image_id=IMAGE_ID):
    verify_image_manifest(payload, "sha256:" + hashlib.sha256(payload).hexdigest(), image_id)


@pytest.mark.parametrize("media_type", MANIFEST_TYPES)
def test_single_platform_manifests(media_type):
    verify(manifest(mediaType=media_type))


@pytest.mark.parametrize(
    "changes",
    [
        {"schemaVersion": True},
        {"mediaType": "application/vnd.oci.image.index.v1+json"},
        {"config": {"digest": "sha256:" + "b" * 64}},
        {"config": None},
        {"layers": None},
    ],
)
def test_manifest_cannot_substitute_other_image_or_index(changes):
    with pytest.raises(ValueError):
        verify(manifest(**changes))


def test_raw_bytes_must_match_digest():
    payload = manifest()
    with pytest.raises(ValueError, match="digest mismatch"):
        verify_image_manifest(payload + b" ", "sha256:" + hashlib.sha256(payload).hexdigest(), IMAGE_ID)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"schemaVersion":2,"schemaVersion":2}',
        b"[]",
        b"null",
        b"not json",
        b"x" * (4 * 1024 * 1024 + 1),
    ],
)
def test_invalid_or_ambiguous_manifest_rejected(payload):
    with pytest.raises(ValueError):
        verify(payload)
