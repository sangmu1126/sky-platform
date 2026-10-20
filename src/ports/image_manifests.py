"""Bind a single-platform registry manifest to the built image config digest."""

import hashlib
import json
import re

MANIFEST_TYPES = (
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
)


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate image manifest field")
        value[key] = item
    return value


def verify_image_manifest(manifest, image_digest, image_id):
    """Verify raw manifest bytes and config identity, not layer availability/signatures."""
    if isinstance(manifest, str):
        manifest = manifest.encode("utf-8")
    if not isinstance(manifest, bytes) or len(manifest) > 4 * 1024 * 1024:
        raise ValueError("Invalid image manifest payload")
    if any(
        not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value)
        for value in (image_digest, image_id)
    ):
        raise ValueError("Invalid registry image identity")
    if "sha256:" + hashlib.sha256(manifest).hexdigest() != image_digest:
        raise ValueError("Registry manifest digest mismatch")
    value = json.loads(manifest, object_pairs_hook=_unique_object)
    if (
        not isinstance(value, dict)
        or type(value.get("schemaVersion")) is not int
        or value["schemaVersion"] != 2
        or value.get("mediaType") not in MANIFEST_TYPES
        or not isinstance(value.get("config"), dict)
        or value["config"].get("digest") != image_id
        or not isinstance(value.get("layers"), list)
    ):
        raise ValueError("Registry manifest does not identify the built single-platform image")
