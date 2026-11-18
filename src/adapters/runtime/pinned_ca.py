"""Descriptor-pinned public CA bundles for registered environment transports."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path

_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_MAX_CA_BYTES = 1024 * 1024


def pinned_ca_bundle(path, expected_sha256=None):
    if expected_sha256 is not None and (
        not isinstance(expected_sha256, str) or not _DIGEST.fullmatch(expected_sha256)
    ):
        raise ValueError("Pinned CA bundle required")
    try:
        value = Path(path)
    except TypeError:
        raise ValueError("Pinned CA bundle required") from None
    if not value.is_absolute():
        raise ValueError("Pinned CA bundle required")
    try:
        descriptor = os.open(
            value,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError:
        raise ValueError("Pinned CA bundle required") from None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 1 <= before.st_size <= _MAX_CA_BYTES
        ):
            raise ValueError("Pinned CA bundle required")
        content = bytearray()
        while len(content) <= _MAX_CA_BYTES:
            chunk = os.read(descriptor, min(65536, _MAX_CA_BYTES + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        if len(content) != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ValueError("Pinned CA bundle changed while reading")
        data = bytes(content)
        digest = hashlib.sha256(data).hexdigest()
        if expected_sha256 is not None and digest != expected_sha256:
            raise ValueError("Pinned CA bundle digest changed")
        try:
            text = data.decode()
        except UnicodeError:
            raise ValueError("Pinned CA bundle required") from None
        if "-----BEGIN CERTIFICATE-----" not in text or "-----END CERTIFICATE-----" not in text:
            raise ValueError("Pinned CA bundle required")
        return data, digest
    finally:
        os.close(descriptor)
