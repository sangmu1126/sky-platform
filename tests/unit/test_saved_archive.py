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
