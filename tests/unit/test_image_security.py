"""Dirty, stale or forged inspection cannot authorize ECR publication."""

import copy
import sys
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

import pytest

from adapters.build import process
from adapters.build.image_security import SCANNER_SHA256, validate_report, validate_security

with patch.dict(sys.modules, {"process": process}):
    from scripts.isolated_scan_guest import normalize


def report():
    return {
        "version": 1,
        "archive_sha256": "a" * 64,
        "scanner_sha256": SCANNER_SHA256,
        "database_sha256": "b" * 64,
        "database_updated_at": datetime.now(UTC).isoformat(),
        "sbom_sha256": "c" * 64,
        "package_count": 1,
        "secret_count": 0,
        "passed": True,
        "vulnerabilities": dict.fromkeys(("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"), 0),
        "offline": True,
        "workload_executed": False,
        "duration_ms": 100,
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"passed": False},
        {"secret_count": 1},
        {"scanner_sha256": "d" * 64},
        {"archive_sha256": "e" * 64},
        {"package_count": 0},
        {"workload_executed": True},
        {"duration_ms": 999999},
        {"database_updated_at": (datetime.now(UTC) - timedelta(hours=73)).isoformat()},
    ],
)
def test_bad_or_incomplete_scan_fails_closed(changes):
    with pytest.raises(ValueError):
        validate_report({**report(), **changes}, "a" * 64)


@pytest.mark.parametrize("severity", ["HIGH", "CRITICAL", "UNKNOWN"])
def test_forged_pass_flag_does_not_hide_findings(severity):
    value = report()
    value["vulnerabilities"][severity] = 1
    with pytest.raises(ValueError):
        validate_report(value, "a" * 64)


def test_separate_vm_materials_and_normal_inventory():
    materials = dict.fromkeys(("base_archive_sha256", "context_sha256", "profile_sha256"), "f" * 64)
    materials.update(build_vm_job=str(uuid4()), scanner_vm_job=str(uuid4()))
    security = {"report": report(), "materials": materials}
    validate_security(security, "a" * 64)
    bad = copy.deepcopy(security)
    bad["materials"]["scanner_vm_job"] = materials["build_vm_job"]
    with pytest.raises(ValueError, match="reuse"):
        validate_security(bad, "a" * 64)


def test_normalization_never_exports_secret_matches_paths_or_environment():
    canary = "synthetic-private-canary-never-export"
    bom, vulnerabilities, secrets = normalize(
        {
            "ArtifactType": "container_image",
            "Results": [
                {
                    "Type": "alpine",
                    "Packages": [{"Name": "musl", "Version": "1.2.5", "FilePath": canary}],
                    "Secrets": [{"Match": canary, "Code": {"Lines": [{"Content": canary}]}}],
                    "Vulnerabilities": [{"Severity": "HIGH", "Description": canary}],
                }
            ],
        }
    )
    assert canary not in str(bom)
    assert vulnerabilities["HIGH"] == 1 and secrets == 1
    assert bom["components"][0]["name"] == "musl"


def test_missing_inventory_is_not_a_clean_image():
    with pytest.raises(ValueError):
        normalize({"ArtifactType": "container_image", "Results": []})
