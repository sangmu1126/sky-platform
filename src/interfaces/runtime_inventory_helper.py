"""Root-installed fixed helper for bounded read-only `/proc` observations."""

import json
import os
import re
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path

from adapters.runtime.workload_inventory import (
    collect_linux_proc_observation,
    validate_linux_runtime_registration_document,
)

_REGISTRY = Path("/etc/sky/runtime-inventory")
_PROC = Path("/proc")


def _registration_document(registration_id, registry_root, *, require_root_ownership):
    if not isinstance(registration_id, str) or not re.fullmatch(r"WRR-[a-f0-9]{64}", registration_id):
        raise ValueError("Exact runtime registration ID required")
    root = Path(registry_root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Plain runtime registration directory required")
    root_metadata = root.stat()
    if root_metadata.st_mode & 0o022 or (require_root_ownership and root_metadata.st_uid != 0):
        raise ValueError("Root-owned immutable runtime registration directory required")
    descriptor = os.open(root / (registration_id + ".json"), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > 256 * 1024
            or metadata.st_mode & 0o022
            or (require_root_ownership and metadata.st_uid != 0)
        ):
            raise ValueError("Root-owned immutable runtime registration required")
        data = bytearray()
        while len(data) <= 256 * 1024:
            chunk = os.read(descriptor, min(65536, 256 * 1024 + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > 256 * 1024:
            raise ValueError("Runtime registration exceeds helper limit")
    finally:
        os.close(descriptor)
    document = validate_linux_runtime_registration_document(json.loads(data))
    if document["runtime_registration_id"] != registration_id:
        raise ValueError("Runtime registration filename differs from content")
    return document


def registered_runtime_observation(
    registration_id,
    *,
    registry_root=_REGISTRY,
    proc_root=_PROC,
    clock=lambda: datetime.now(UTC),
    require_root_ownership=True,
):
    document = _registration_document(
        registration_id,
        registry_root,
        require_root_ownership=require_root_ownership,
    )
    return collect_linux_proc_observation(document, proc_root, clock=clock)


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 4 or arguments[0] != "--registration" or arguments[2:] != ["--format", "json-v1"]:
        raise SystemExit("fixed runtime inventory arguments required")
    try:
        observation = registered_runtime_observation(arguments[1])
    except Exception:  # noqa: BLE001 -- never print proc paths or registration diagnostics
        raise SystemExit("runtime observation unavailable") from None
    print(json.dumps(observation, sort_keys=True, separators=(",", ":"), allow_nan=False))
