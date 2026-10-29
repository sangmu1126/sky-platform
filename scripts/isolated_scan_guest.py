"""Offline image parsing in a NEW sealed VM, never in a credentialed publisher.

Only the normalized BOM and counts leave this VM. Secret matches, paths, image
configuration and raw scanner logs are not returned to the controller or AI.
"""

import hashlib
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone

UTC = timezone.utc  # noqa: UP017 -- trusted AL2023 guest uses Python 3.9
from pathlib import Path

from process import bounded_command

STAGE = "initialization"

ROOT = Path("/home/ec2-user")
TRIVY_SHA256 = "d1dfca6ae10a1ad4540bb94e64f0510077c47008920a9b554986b39dca573d83"


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize(raw):
    if not isinstance(raw, dict) or raw.get("ArtifactType") != "container_image":
        raise ValueError("Successful image scan required")
    results = raw.get("Results")
    if not isinstance(results, list) or not results or len(results) > 10000:
        raise ValueError("Missing image package inventory is not a clean result")
    packages, vulnerabilities, secrets = (
        {},
        dict.fromkeys(("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"), 0),
        0,
    )
    for result in results:
        for value in result.get("Vulnerabilities", []):
            severity = value.get("Severity")
            if severity not in vulnerabilities:
                raise ValueError("Unknown vulnerability classification")
            vulnerabilities[severity] += 1
        secrets += len(result.get("Secrets", []))
        for value in result.get("Packages", []):
            name, version = value.get("Name"), value.get("Version")
            if any(
                not isinstance(v, str) or not 1 <= len(v) <= 256 or any(ord(c) < 32 for c in v)
                for v in (name, version)
            ):
                raise ValueError("Bounded package identity required")
            key = hashlib.sha256(json.dumps([result.get("Type"), name, version]).encode()).hexdigest()
            packages[key] = {"type": "library", "bom-ref": key, "name": name, "version": version}
    if not packages or len(packages) > 20000:
        raise ValueError("Missing or oversized image inventory")
    return (
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [packages[k] for k in sorted(packages)],
        },
        vulnerabilities,
        secrets,
    )


def database_timestamp(value):
    # AL2023's supported distro Python is 3.9. Normalize nanoseconds and Z.
    stamp = value.replace("Z", "+00:00")
    stamp = re.sub(r"(\.\d{6})\d+([+-])", r"\1\2", stamp)
    return datetime.fromisoformat(stamp)


def main():
    global STAGE
    if any(
        k in os.environ
        for k in ("AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "OPENAI_API_KEY")
    ):
        raise ValueError("Scanner VM must not have credentials")
    settings = json.loads((ROOT / "scan-settings.json").read_bytes())
    if sha(ROOT / "trivy") != TRIVY_SHA256 or sha(ROOT / "scan-image.tar") != settings["archive_sha256"]:
        raise ValueError("Pinned scanner and image bytes required")
    if sha(ROOT / "scanner-db.tar") != settings["database_sha256"]:
        raise ValueError("Offline vulnerability database changed")
    STAGE = "offline_database"
    import tarfile

    cache = ROOT / "scanner-cache"
    cache.mkdir(mode=0o700)
    with tarfile.open(ROOT / "scanner-db.tar", "r:gz") as archive:
        members = archive.getmembers()
        if {m.name for m in members} != {"db/trivy.db", "db/metadata.json"} or any(
            not m.isfile() for m in members
        ):
            raise ValueError("Only the pinned vulnerability database is accepted")
        if sum(m.size for m in members) > 2 * 1024**3:
            raise ValueError("Vulnerability database exceeds size limit")
        archive.extractall(cache, members=members, filter="data")
    metadata = json.loads((cache / "db/metadata.json").read_bytes())
    updated = database_timestamp(metadata["UpdatedAt"])
    now = datetime.now(UTC)
    if updated.tzinfo is None or not now - timedelta(hours=72) <= updated <= now + timedelta(minutes=5):
        raise ValueError("Stale offline vulnerability database")
    os.chmod(ROOT / "trivy", 0o755)
    STAGE = "scanner_execution"
    started = time.monotonic()
    code, _ = bounded_command(
        [
            "systemd-run",
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            "--slice=sky-build.slice",
            "--property=NoNewPrivileges=yes",
            "--property=PrivateTmp=yes",
            "--property=ProtectSystem=strict",
            "--property=ReadWritePaths=/home/ec2-user",
            "--property=RestrictAddressFamilies=AF_UNIX",
            str(ROOT / "trivy"),
            "image",
            "--input",
            str(ROOT / "scan-image.tar"),
            "--cache-dir",
            str(cache),
            "--skip-db-update",
            "--skip-java-db-update",
            "--offline-scan",
            "--skip-check-update",
            "--scanners",
            "vuln,secret",
            "--list-all-pkgs",
            "--parallel",
            "1",
            "--timeout",
            "3m",
            "--format",
            "json",
            "--output",
            str(ROOT / "raw-scan.json"),
        ],
        timeout=210,
        output_limit=1024 * 1024,
    )
    if (
        code
        or not (ROOT / "raw-scan.json").is_file()
        or (ROOT / "raw-scan.json").stat().st_size > 16 * 1024**2
    ):
        raise OSError("Offline scanner failed; publication denied")
    STAGE = "inventory_normalization"
    bom, vulnerabilities, secrets = normalize(json.loads((ROOT / "raw-scan.json").read_bytes()))
    (ROOT / "raw-scan.json").unlink()
    bom_bytes = json.dumps(bom, sort_keys=True, separators=(",", ":")).encode()
    (ROOT / "sbom.json").write_bytes(bom_bytes)
    report = {
        "version": 1,
        "archive_sha256": settings["archive_sha256"],
        "scanner_sha256": TRIVY_SHA256,
        "database_sha256": settings["database_sha256"],
        "database_updated_at": updated.isoformat(),
        "sbom_sha256": hashlib.sha256(bom_bytes).hexdigest(),
        "package_count": len(bom["components"]),
        "vulnerabilities": vulnerabilities,
        "secret_count": secrets,
        "passed": not (
            secrets or vulnerabilities["HIGH"] or vulnerabilities["CRITICAL"] or vulnerabilities["UNKNOWN"]
        ),
        "offline": True,
        "workload_executed": False,
        "duration_ms": int((time.monotonic() - started) * 1000),
    }
    (ROOT / "scan.json").write_text(json.dumps(report, sort_keys=True, separators=(",", ":")))
    print(json.dumps({"scan_completed": True, "passed": report["passed"]}))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # noqa: BLE001 -- emit fixed stage/type only, never raw scanner data
        print(json.dumps({"inspection_failure_stage": STAGE, "error_type": type(error).__name__}))
        raise SystemExit(1) from None
