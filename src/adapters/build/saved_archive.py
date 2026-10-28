"""Validate a restricted plain Docker-save tar as data before acquiring AWS clients.

No extraction, layer execution, compressed outer tar or extended tar headers.
Fixed headers avoid allocating attacker-sized PAX records. Layer content can
still be malicious; this is format/identity checking, not a safe-image proof.
"""

import hashlib
import json
import os
import stat
import tarfile
from pathlib import PurePosixPath

MAX_ARCHIVE = 4 * 1024**3
MAX_METADATA = 2 * 1024**2
MAX_TOTAL_METADATA = 16 * 1024**2
INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
MANIFEST_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}


def _document(payload):
    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("Duplicate saved image metadata field")
            result[name] = value
        return result

    return json.loads(payload, object_pairs_hook=unique)


def validate_saved_archive(path, image_id, tag, *, platform="linux/amd64"):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    files, documents, hashes = set(), {}, {}
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or not 1024 <= info.st_size <= MAX_ARCHIVE:
            raise ValueError("Saved image archive exceeds the supported bound")
        entries, expanded, metadata_bytes = 0, 0, 0
        while True:
            header = source.read(512)
            if len(header) != 512:
                raise ValueError("Saved image tar is truncated")
            if not any(header):
                while rest := source.read(65536):
                    if any(rest):
                        raise ValueError("Saved image has data after the tar terminator")
                break
            try:
                member = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
            except (tarfile.HeaderError, UnicodeError):
                raise ValueError("Saved image tar header is invalid") from None
            entries += 1
            expanded += member.size
            name = member.name.rstrip("/")
            parsed = PurePosixPath(name)
            if (
                entries > 20000
                or expanded > MAX_ARCHIVE
                or member.size < 0
                or not name
                or len(name.encode()) > 1024
                or parsed.is_absolute()
                or ".." in parsed.parts
                or parsed.as_posix() != name
                or "\\" in name
                or any(ord(c) < 32 for c in name)
                or name in files
                or member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}
            ):
                raise ValueError("Saved image contains unsupported paths or tar records")
            files.add(name)
            if member.isdir():
                if member.size:
                    raise ValueError("Saved image directory has a payload")
                continue
            if member.size <= MAX_METADATA:
                metadata_bytes += member.size
                if metadata_bytes > MAX_TOTAL_METADATA:
                    raise ValueError("Saved image metadata exceeds the aggregate bound")
            digest, payload = hashlib.sha256(), bytearray()
            remaining = member.size
            while remaining:
                chunk = source.read(min(65536, remaining))
                if not chunk:
                    raise ValueError("Saved image member is truncated")
                digest.update(chunk)
                if member.size <= MAX_METADATA:
                    payload.extend(chunk)
                remaining -= len(chunk)
            hashes[name] = digest.hexdigest()
            if member.size <= MAX_METADATA:
                documents[name] = bytes(payload)
            padding = source.read((-member.size) % 512)
            if len(padding) != (-member.size) % 512:
                raise ValueError("Saved image member padding is truncated")
    try:
        manifests = _document(documents["manifest.json"])
        if not isinstance(manifests, list) or len(manifests) != 1:
            raise ValueError()
        manifest = manifests[0]
        if manifest.get("RepoTags") != [tag] or not isinstance(manifest.get("Layers"), list):
            raise ValueError()
        config_name = manifest["Config"]
        config_digest = "sha256:" + hashes[config_name]
        if image_id is not None and config_digest != image_id:
            raise ValueError()
        config = _document(documents[config_name])
        if config.get("os") + "/" + config.get("architecture") != platform:
            raise ValueError()
        if any(not isinstance(name, str) or name not in hashes for name in manifest["Layers"]):
            raise ValueError()
        for name, digest in hashes.items():
            if name.startswith("blobs/sha256/") and name.removeprefix("blobs/sha256/") != digest:
                raise ValueError()
        identities = {config_digest}
        if "index.json" in documents:
            index = _document(documents["index.json"])
            roots = index["manifests"]
            if not isinstance(roots, list) or len(roots) != 1:
                raise ValueError()

            def linked(descriptor, depth=0):
                if depth > 3 or not isinstance(descriptor, dict):
                    raise ValueError()
                digest = descriptor["digest"]
                path = "blobs/sha256/" + digest.removeprefix("sha256:")
                if digest != "sha256:" + hashes[path]:
                    raise ValueError()
                body = _document(documents[path])
                media_type = descriptor["mediaType"]
                if (
                    not isinstance(body, dict)
                    or body.get("schemaVersion") != 2
                    or body.get("mediaType", media_type) != media_type
                    or descriptor.get("size") != len(documents[path])
                ):
                    raise ValueError()
                if media_type in MANIFEST_TYPES:
                    if body["config"]["digest"] != config_digest:
                        raise ValueError()
                    layers = [
                        "blobs/sha256/" + layer["digest"].removeprefix("sha256:") for layer in body["layers"]
                    ]
                    if layers != manifest["Layers"]:
                        raise ValueError()
                elif media_type in INDEX_TYPES:
                    if not isinstance(body.get("manifests"), list) or len(body["manifests"]) > 64:
                        raise ValueError()
                    selected = [
                        item
                        for item in body["manifests"]
                        if isinstance(item, dict)
                        and isinstance(item.get("platform"), dict)
                        and item["platform"].get("os") + "/" + item["platform"].get("architecture")
                        == platform
                    ]
                    if len(selected) != 1:
                        raise ValueError()
                    linked(selected[0], depth + 1)
                else:
                    raise ValueError()
                identities.add(digest)

            linked(roots[0])
    except (KeyError, ValueError, TypeError, AttributeError, RecursionError):
        raise ValueError("Saved image manifest/config differs from the build receipt") from None
    return {
        "archive_bytes": info.st_size,
        "entries": entries,
        "platform": platform,
        "config_digest": config_digest,
        "image_identities": sorted(identities),
        "code_executed": False,
    }
