"""Prepare registry blobs as bounded data. Never load, extract or run an image."""

import gzip
import hashlib
import json
import os
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from adapters.build.saved_archive import MAX_ARCHIVE, validate_saved_archive

OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
LAYER_TYPES = {
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
    "application/vnd.oci.image.layer.v1.tar",
}


@contextmanager
def registry_image(archive, image_id, tag, *, platform="linux/amd64"):
    checked = validate_saved_archive(archive, image_id, tag, platform=platform, include_layout=True)
    selected = checked["docker_manifest"]
    members = checked["members"]
    if len(selected["Layers"]) > 256:
        raise ValueError("Bounded image layer count required")
    deadline = time.monotonic() + 180
    with tempfile.TemporaryDirectory(prefix="sky-registry-data-") as directory:
        blobs, total = {}, 0
        descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as source:

            def copy(name, *, compress=False):
                nonlocal total
                item = members[name]
                source.seek(item["offset"])
                path = Path(directory) / item["sha256"]
                remaining, digest = item["size"], hashlib.sha256()
                with path.open("wb") as output:
                    target = (
                        gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) if compress else output
                    )
                    try:
                        while remaining:
                            if time.monotonic() > deadline:
                                raise ValueError("Registry data preparation exceeded time bound")
                            chunk = source.read(min(65536, remaining))
                            if not chunk:
                                raise ValueError("Registry source changed after validation")
                            digest.update(chunk)
                            target.write(chunk)
                            remaining -= len(chunk)
                    finally:
                        if compress:
                            target.close()
                if digest.hexdigest() != item["sha256"]:
                    raise ValueError("Registry source changed after validation")
                size = path.stat().st_size
                total += size
                if total > MAX_ARCHIVE + 16 * 1024**2:
                    raise ValueError("Registry prepared data exceeds disk bound")
                with path.open("rb") as payload:
                    identity = "sha256:" + hashlib.file_digest(payload, "sha256").hexdigest()
                blobs[identity] = path
                return {"digest": identity, "size": size}

            config = copy(selected["Config"])
            if config["digest"] != image_id:
                raise ValueError("Registry config differs from approved receipt")
            config_body = json.loads(blobs[image_id].read_bytes())
            rootfs = config_body.get("rootfs")
            if (
                not isinstance(rootfs, dict)
                or rootfs.get("type") != "layers"
                or not isinstance(rootfs.get("diff_ids"), list)
                or len(rootfs["diff_ids"]) != len(selected["Layers"])
            ):
                raise ValueError("Exact root filesystem identities required")
            manifest = checked["registry_manifest"]
            if manifest is not None:
                layers = []
                for index, (name, layer) in enumerate(zip(selected["Layers"], manifest["layers"], strict=True)):
                    if layer.get("mediaType") not in LAYER_TYPES:
                        raise ValueError("Registry layer media type is unsupported")
                    original = {"digest": "sha256:" + members[name]["sha256"], "size": members[name]["size"]}
                    if any(original[k] != layer.get(k) for k in ("digest", "size")):
                        raise ValueError("Registry layer descriptor differs from blob")
                    uncompressed = layer["mediaType"] == "application/vnd.oci.image.layer.v1.tar"
                    if uncompressed and rootfs["diff_ids"][index] != original["digest"]:
                        raise ValueError("Registry uncompressed layer differs from config")
                    actual = copy(name, compress=uncompressed)
                    layers.append({**layer, **actual, "mediaType": (
                        "application/vnd.oci.image.layer.v1.tar+gzip" if uncompressed else layer["mediaType"])})
                if any(config[k] != manifest["config"].get(k) for k in ("digest", "size")):
                    raise ValueError("Registry config descriptor differs from blob")
                manifest = {**manifest, "layers": layers}
            else:
                layers = []
                for index, name in enumerate(selected["Layers"]):
                    if rootfs["diff_ids"][index] != "sha256:" + members[name]["sha256"]:
                        raise ValueError("Registry uncompressed layer differs from config")
                    layers.append(
                        {
                            **copy(name, compress=True),
                            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                        }
                    )
                manifest = {
                    "schemaVersion": 2,
                    "mediaType": OCI_MANIFEST,
                    "config": {**config, "mediaType": OCI_CONFIG},
                    "layers": layers,
                }
            raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
            yield {
                "manifest": raw,
                "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "media_type": manifest.get("mediaType", OCI_MANIFEST),
                "blobs": blobs,
                "config_digest": image_id,
                "code_executed": False,
            }
