"""Host paths, links, duplicate entries and unexpected image identity are rejected."""

import hashlib
import io
import json
import tarfile

import pytest

from adapters.build.saved_archive import validate_saved_archive


def archive(path, extra=None):
    config = b'{"os":"linux","architecture":"amd64","config":{}}'
    digest = hashlib.sha256(config).hexdigest()
    name = digest + ".json"
    files = {
        name: config,
        "manifest.json": json.dumps(
            [{"Config": name, "RepoTags": ["sky-build:test"], "Layers": []}]
        ).encode(),
    }
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as output:
        for key, data in files.items():
            item = tarfile.TarInfo(key)
            item.size = len(data)
            output.addfile(item, io.BytesIO(data))
        if extra is not None:
            output.addfile(extra, io.BytesIO(b"x" * extra.size))
    return "sha256:" + digest


def test_plain_image_metadata_is_checked_without_extraction(tmp_path):
    path = tmp_path / "image.tar"
    identity = archive(path)
    receipt = validate_saved_archive(path, identity, "sky-build:test")
    assert receipt["config_digest"] == identity and not receipt["code_executed"]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["image.tar"]


@pytest.mark.parametrize(
    "name,kind",
    [
        ("../escape", tarfile.REGTYPE),
        ("/absolute", tarfile.REGTYPE),
        ("linked", tarfile.SYMTYPE),
        ("metadata", tarfile.XHDTYPE),
        ("manifest.json", tarfile.REGTYPE),
    ],
)
def test_unsafe_members_never_reach_image_loading(tmp_path, name, kind):
    item = tarfile.TarInfo(name)
    item.type = kind
    item.linkname = "/etc/passwd" if kind == tarfile.SYMTYPE else ""
    path = tmp_path / "image.tar"
    identity = archive(path, item)
    with pytest.raises(ValueError):
        validate_saved_archive(path, identity, "sky-build:test")


def test_wrong_config_digest_or_tag_is_rejected(tmp_path):
    path = tmp_path / "image.tar"
    identity = archive(path)
    with pytest.raises(ValueError):
        validate_saved_archive(path, "sha256:" + "0" * 64, "sky-build:test")
    with pytest.raises(ValueError):
        validate_saved_archive(path, identity, "sky-build:other")


def test_duplicate_json_fields_are_rejected_even_when_last_value_matches(tmp_path):
    path = tmp_path / "image.tar"
    config = b'{"os":"linux","architecture":"arm64","architecture":"amd64"}'
    name = hashlib.sha256(config).hexdigest() + ".json"
    files = {
        name: config,
        "manifest.json": json.dumps(
            [{"Config": name, "RepoTags": ["sky-build:test"], "Layers": []}]
        ).encode(),
    }
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as output:
        for key, payload in files.items():
            item = tarfile.TarInfo(key)
            item.size = len(payload)
            output.addfile(item, io.BytesIO(payload))
    with pytest.raises(ValueError):
        validate_saved_archive(path, "sha256:" + hashlib.sha256(config).hexdigest(), "sky-build:test")


@pytest.mark.parametrize("ambiguous", [False, True])
def test_containerd_index_must_bind_one_platform_manifest_to_receipt(tmp_path, ambiguous):
    files = {}

    def blob(document):
        payload = json.dumps(document).encode()
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        files["blobs/sha256/" + digest.split(":")[1]] = payload
        return {"digest": digest, "size": len(payload)}

    config = blob({"os": "linux", "architecture": "amd64"})
    manifest = blob({"schemaVersion": 2, "config": config, "layers": []})
    manifest["mediaType"] = "application/vnd.oci.image.manifest.v1+json"
    manifest["platform"] = {"os": "linux", "architecture": "amd64"}
    root = blob({"schemaVersion": 2, "manifests": [manifest] * (2 if ambiguous else 1)})
    root["mediaType"] = "application/vnd.oci.image.index.v1+json"
    files["index.json"] = json.dumps({"schemaVersion": 2, "manifests": [root]}).encode()
    files["manifest.json"] = json.dumps(
        [
            {
                "Config": "blobs/sha256/" + config["digest"].split(":")[1],
                "RepoTags": ["sky-build:test"],
                "Layers": [],
            }
        ]
    ).encode()
    path = tmp_path / "image.tar"
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as output:
        for key, payload in files.items():
            item = tarfile.TarInfo(key)
            item.size = len(payload)
            output.addfile(item, io.BytesIO(payload))
    if ambiguous:
        with pytest.raises(ValueError):
            validate_saved_archive(path, config["digest"], "sky-build:test")
    else:
        result = validate_saved_archive(path, config["digest"], "sky-build:test")
        assert set(result["image_identities"]) == {config["digest"], manifest["digest"], root["digest"]}


def test_aggregate_metadata_bound_prevents_many_small_members(tmp_path, monkeypatch):
    import adapters.build.saved_archive as validator

    path = tmp_path / "image.tar"
    identity = archive(path)
    monkeypatch.setattr(validator, "MAX_TOTAL_METADATA", 32)
    with pytest.raises(ValueError, match="aggregate bound"):
        validate_saved_archive(path, identity, "sky-build:test")


@pytest.mark.parametrize("change", [None, "foreign-subject", "second-platform", "altered-attachment"])
def test_only_attached_provenance_beside_one_platform_is_inert_data(tmp_path, change):
    files = {}

    def blob(body):
        raw = json.dumps(body).encode()
        identity = "sha256:" + hashlib.sha256(raw).hexdigest()
        files["blobs/sha256/" + identity.split(":")[1]] = raw
        return {"digest": identity, "size": len(raw)}

    config = blob({"os": "linux", "architecture": "amd64"})
    image = blob({"schemaVersion": 2, "config": config, "layers": []})
    image.update(
        mediaType="application/vnd.oci.image.manifest.v1+json",
        platform={"os": "linux", "architecture": "amd64"},
    )
    attached = blob({"schemaVersion": 2, "artifactType": "application/vnd.in-toto+json"})
    attached.update(
        mediaType="application/vnd.oci.image.manifest.v1+json",
        annotations={"io.containerd.manifest.subject": image["digest"]},
    )
    if change == "foreign-subject":
        attached["annotations"]["io.containerd.manifest.subject"] = "sha256:" + "0" * 64
    elif change == "second-platform":
        attached["platform"] = {"os": "linux", "architecture": "amd64"}
    elif change == "altered-attachment":
        attached["size"] += 1
    files["index.json"] = json.dumps({"schemaVersion": 2, "manifests": [image, attached]}).encode()
    files["manifest.json"] = json.dumps(
        [
            {
                "Config": "blobs/sha256/" + config["digest"].split(":")[1],
                "RepoTags": ["sky-build:test"],
                "Layers": [],
            }
        ]
    ).encode()
    path = tmp_path / "image.tar"
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in files.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    if change is None:
        result = validate_saved_archive(path, config["digest"], "sky-build:test")
        assert attached["digest"] not in result["image_identities"]
    else:
        with pytest.raises(ValueError):
            validate_saved_archive(path, config["digest"], "sky-build:test")
