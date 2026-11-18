"""Content-addressed image-definition equality, not running-host attestation.

Provider/daemon identity checks and actual workload verification are caller
responsibilities. An OCI index alone can contain different platform images;
exactly one registered platform manifest and its config/rootfs must be checked.
"""

import hashlib
import json
import re


def _digest(raw, expected, limit):
    if (
        not isinstance(raw, bytes)
        or len(raw) > limit
        or not isinstance(expected, str)
        or not re.fullmatch(r"sha256:[a-f0-9]{64}", expected)
        or "sha256:" + hashlib.sha256(raw).hexdigest() != expected
    ):
        raise ValueError("Exact bounded image content digest required")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Ambiguous image manifest field")
            result[key] = value
        return result

    document = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(document, dict):
        raise ValueError("Image manifest object required")  # noqa: TRY004 -- invalid encoded content
    return document


def verify_platform_image(
    index_bytes,
    manifest_bytes,
    config_bytes,
    *,
    expected_index_digest,
    platform_os,
    architecture,
    observed_rootfs,
):
    if not isinstance(manifest_bytes, bytes) or not isinstance(config_bytes, bytes):
        raise TypeError("Image manifest/config bytes required")
    if (
        platform_os != "linux"
        or architecture not in {"arm64", "amd64"}
        or not isinstance(observed_rootfs, tuple)
    ):
        raise ValueError("Explicit qualified Linux platform required")
    index = _digest(index_bytes, expected_index_digest, 65536)
    if index.get("schemaVersion") != 2 or index.get("mediaType") != "application/vnd.oci.image.index.v1+json":
        raise ValueError("Qualified OCI index required")
    entries = index.get("manifests")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 16:
        raise ValueError("Bounded platform manifests required")
    if any(not isinstance(v, dict) or not isinstance(v.get("platform", {}), dict) for v in entries):
        raise ValueError("Typed platform manifest descriptors required")
    matches = [
        v
        for v in entries
        if isinstance(v, dict)
        and v.get("platform", {}).get("architecture") == architecture
        and v.get("platform", {}).get("os") == platform_os
    ]
    if len(matches) != 1:
        raise ValueError("Exactly one matching platform manifest required")
    descriptor = matches[0]
    if descriptor.get("mediaType") != "application/vnd.oci.image.manifest.v1+json" or descriptor.get(
        "size"
    ) != len(manifest_bytes):
        raise ValueError("Matching manifest descriptor required")
    manifest = _digest(manifest_bytes, descriptor["digest"], 65536)
    if (
        manifest.get("schemaVersion") != 2
        or manifest.get("mediaType") != "application/vnd.oci.image.manifest.v1+json"
    ):
        raise ValueError("Qualified OCI platform manifest required")
    config_descriptor = manifest.get("config", {})
    if not isinstance(config_descriptor, dict):
        raise ValueError("Typed image configuration descriptor required")  # noqa: TRY004 -- encoded content
    if config_descriptor.get(
        "mediaType"
    ) != "application/vnd.oci.image.config.v1+json" or config_descriptor.get("size") != len(config_bytes):
        raise ValueError("Matching image configuration descriptor required")
    config = _digest(config_bytes, config_descriptor["digest"], 256 * 1024)
    rootfs = config.get("rootfs")
    if not isinstance(rootfs, dict):
        raise ValueError("Typed image rootfs definition required")  # noqa: TRY004 -- encoded content
    layers = rootfs.get("diff_ids")
    if (
        config.get("os") != platform_os
        or config.get("architecture") != architecture
        or rootfs.get("type") != "layers"
        or not isinstance(layers, list)
        or not 1 <= len(layers) <= 256
        or any(not isinstance(v, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", v) for v in layers)
        or tuple(layers) != observed_rootfs
    ):
        raise ValueError("Observed platform or rootfs layer definition differs")
    return {
        "schema_version": 1,
        "index_digest": expected_index_digest,
        "platform_manifest_digest": descriptor["digest"],
        "config_digest": config_descriptor["digest"],
        "platform_os": platform_os,
        "architecture": architecture,
        "rootfs_definition_sha256": hashlib.sha256(
            json.dumps(layers, separators=(",", ":")).encode()
        ).hexdigest(),
        "verified_scope": "content_addressed_image_definition",
        "running_host_integrity_attested": False,
        "execution_authorized": False,
    }
