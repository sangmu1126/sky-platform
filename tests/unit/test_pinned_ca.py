"""Registered public CA bundles are read once through a stable descriptor."""

import hashlib
import os
from unittest.mock import patch

import pytest

from adapters.runtime.pinned_ca import pinned_ca_bundle

CA = b"-----BEGIN CERTIFICATE-----\npublic-ca\n-----END CERTIFICATE-----\n"


def bundle(tmp_path):
    path = tmp_path / "ca.pem"
    path.write_bytes(CA)
    return path, hashlib.sha256(CA).hexdigest()


def test_pinned_ca_returns_the_exact_descriptor_bytes_and_digest(tmp_path):
    path, digest = bundle(tmp_path)
    assert pinned_ca_bundle(path, digest) == (CA, digest)
    assert pinned_ca_bundle(path) == (CA, digest)


@pytest.mark.parametrize("expected", ["", "A" * 64, "0" * 63, 7])
def test_noncanonical_expected_digest_is_rejected_before_open(tmp_path, expected):
    path, _digest = bundle(tmp_path)
    with (
        patch("adapters.runtime.pinned_ca.os.open") as opened,
        pytest.raises(ValueError, match="Pinned CA bundle"),
    ):
        pinned_ca_bundle(path, expected)
    opened.assert_not_called()


@pytest.mark.parametrize("content", [b"", b"not-a-certificate", b"\xff\xfe"])
def test_empty_non_pem_or_non_utf8_bundle_is_rejected(tmp_path, content):
    path = tmp_path / "ca.pem"
    path.write_bytes(content)
    with pytest.raises(ValueError, match="Pinned CA bundle"):
        pinned_ca_bundle(path)


def test_relative_missing_symlink_directory_and_oversized_bundle_are_rejected(tmp_path):
    path, _digest = bundle(tmp_path)
    link = tmp_path / "link.pem"
    link.symlink_to(path)
    directory = tmp_path / "directory.pem"
    directory.mkdir()
    oversized = tmp_path / "oversized.pem"
    oversized.write_bytes(CA + b"x" * (1024 * 1024))
    for invalid in ("relative.pem", tmp_path / "missing.pem", link, directory, oversized, None):
        with pytest.raises(ValueError, match="Pinned CA bundle"):
            pinned_ca_bundle(invalid)


@pytest.mark.parametrize("mode", [0o664, 0o646, 0o666])
def test_group_or_world_writable_bundle_is_rejected(tmp_path, mode):
    path, _digest = bundle(tmp_path)
    path.chmod(mode)
    with pytest.raises(ValueError, match="Pinned CA bundle"):
        pinned_ca_bundle(path)


def test_digest_or_descriptor_metadata_change_is_rejected(tmp_path):
    path, digest = bundle(tmp_path)
    with pytest.raises(ValueError, match="digest changed"):
        pinned_ca_bundle(path, "0" * 64)

    original = os.read
    changed = False

    def mutate_mode(descriptor, size):
        nonlocal changed
        content = original(descriptor, size)
        if not changed:
            os.fchmod(descriptor, 0o666)
            changed = True
        return content

    with (
        patch("adapters.runtime.pinned_ca.os.read", side_effect=mutate_mode),
        pytest.raises(ValueError, match="changed while reading"),
    ):
        pinned_ca_bundle(path, digest)
