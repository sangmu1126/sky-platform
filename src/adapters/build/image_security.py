"""Bounded security receipts; scanner output never grants deployment authority."""

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

SCANNER_SHA256 = "d1dfca6ae10a1ad4540bb94e64f0510077c47008920a9b554986b39dca573d83"


def sha(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def checked_document(path, limit):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Plain bounded security artifact required")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if not 0 < len(raw) <= limit:
        raise ValueError("Security artifact exceeds bound")
    return json.loads(raw)


def validate_report(report, archive_sha256, *, now=None):
    now = now or datetime.now(UTC)
    fields = {
        "version",
        "archive_sha256",
        "scanner_sha256",
        "database_sha256",
        "database_updated_at",
        "sbom_sha256",
        "package_count",
        "vulnerabilities",
        "secret_count",
        "passed",
        "offline",
        "workload_executed",
        "duration_ms",
    }
    if not isinstance(report, dict) or set(report) != fields:
        raise ValueError("Exact completed image inspection required")
    for key in ("archive_sha256", "scanner_sha256", "database_sha256", "sbom_sha256"):
        if not isinstance(report[key], str) or not re.fullmatch("[a-f0-9]{64}", report[key]):
            raise ValueError("Exact security artifact identities required")
    levels = report["vulnerabilities"]
    if (
        type(report["version"]) is not int
        or report["version"] != 1
        or report["archive_sha256"] != archive_sha256
        or report["scanner_sha256"] != SCANNER_SHA256
        or report["offline"] is not True
        or report["workload_executed"] is not False
        or report["passed"] is not True
        or type(report["package_count"]) is not int
        or not 1 <= report["package_count"] <= 20000
        or type(report["duration_ms"]) is not int
        or not 0 <= report["duration_ms"] <= 210000
        or type(report["secret_count"]) is not int
        or report["secret_count"] != 0
        or not isinstance(levels, dict)
        or set(levels) != {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
        or any(type(v) is not int or not 0 <= v <= 100000 for v in levels.values())
        or any(levels[k] for k in ("UNKNOWN", "HIGH", "CRITICAL"))
    ):
        raise ValueError("Image security findings or incomplete inspection block publication")
    updated = datetime.fromisoformat(report["database_updated_at"])
    if updated.tzinfo is None or not now - timedelta(hours=72) <= updated <= now + timedelta(minutes=5):
        raise ValueError("Offline security database is stale")
    return report


def validate_security(security, archive_sha256):
    if not isinstance(security, dict) or set(security) not in (
        {"report", "materials"},
        {"report", "materials", "usage"},
    ):
        raise ValueError("Signed image security and build materials required")
    validate_report(security["report"], archive_sha256)
    m = security["materials"]
    if not isinstance(m, dict) or set(m) != {
        "base_archive_sha256",
        "context_sha256",
        "profile_sha256",
        "build_vm_job",
        "scanner_vm_job",
    }:
        raise ValueError("Exact isolated build materials required")
    for key in ("base_archive_sha256", "context_sha256", "profile_sha256"):
        if not isinstance(m[key], str) or not re.fullmatch("[a-f0-9]{64}", m[key]):
            raise ValueError("Pinned build material identity required")
    for key in ("build_vm_job", "scanner_vm_job"):
        if not isinstance(m[key], str) or str(UUID(m[key])) != m[key]:
            raise ValueError("Exact isolated stage identity required")
    if m["build_vm_job"] == m["scanner_vm_job"]:
        raise ValueError("Inspection must not reuse the workload execution VM")
    if "usage" in security:
        usage = security["usage"]
        if (
            not isinstance(usage, dict)
            or set(usage) != {"build_seconds", "source", "cost_measured", "reservation_released"}
            or type(usage["build_seconds"]) is not int
            or not 1 <= usage["build_seconds"] <= 7200
            or usage["source"] != "trusted_controller_elapsed_upper"
            or usage["cost_measured"] is not False
            or usage["reservation_released"] is not False
        ):
            raise ValueError("Bounded measured build usage without billing/refund claims required")
    return security


def publication_security(output, archive_sha256):
    from scripts.validate_sbom import validate

    report = checked_document(output / "scan.json", 8192)
    bom = checked_document(output / "sbom.json", 1024 * 1024)
    if (
        sha(output / "sbom.json") != report["sbom_sha256"]
        or len(bom.get("components", [])) != report["package_count"]
    ):
        raise ValueError("Image BOM differs from the inspected artifact")
    validate(bom, Path(__file__).resolve().parents[3] / "security/schemas/cyclonedx-1.6")
    return validate_security(
        {
            "report": report,
            "materials": checked_document(output / "materials.json", 8192),
            "usage": checked_document(output / "usage.json", 8192),
        },
        archive_sha256,
    )
