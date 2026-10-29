"""Check trusted guest helpers on distro Python, without AWS, Docker or user code."""

import hashlib
import importlib.util
import json
import runpy
import sys
import tempfile
from pathlib import Path


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    root = Path(__file__).resolve().parents[1]
    for name in ("process", "offline"):
        load(name, root / "src/adapters/build" / (name + ".py"))
    scanner = runpy.run_path(str(root / "scripts/isolated_scan_guest.py"))
    guest = runpy.run_path(str(root / "scripts/isolated_guest.py"))
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "plain"
        path.write_bytes(b"public synthetic fixture")
        assert scanner["sha"](path) == hashlib.sha256(path.read_bytes()).hexdigest()
    stamp = scanner["database_timestamp"]("2026-10-29T13:09:46.269823229Z")
    assert stamp.microsecond == 269823 and stamp.utcoffset().total_seconds() == 0
    bom, _, count = scanner["normalize"](
        {
            "ArtifactType": "container_image",
            "Results": [
                {"Packages": [{"Name": "normal", "Version": "1"}], "Secrets": [{"Match": "synthetic-canary"}]}
            ],
        }
    )
    assert count == 1 and "synthetic-canary" not in str(bom)
    proof = guest["rehearse"]("unused", "sha256:" + "a" * 64, {"target_verification_required": True})
    assert proof["status"] == "requires_target_verification" and proof["credentials_used"] is False
    print(json.dumps({"trusted_guest_runtime": "checked", "network_calls": 0, "user_code_executed": False}))


if __name__ == "__main__":
    main()
