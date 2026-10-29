"""Keyless defense acceptance report; never represents a live-model red team."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

CASES = {
    "D01": ["tests/unit/test_build_execution_grants.py", "tests/contract/test_build_delegation.py"],
    "D02": ["tests/unit/test_adversarial_source_boundary.py"],
    "D03": ["tests/unit/test_build_sandbox.py", "tests/unit/test_vm_build_context.py"],
    "D04": ["tests/unit/test_patch_security.py"],
    "D05": [
        "tests/contract/test_effect_budget.py",
        "tests/contract/test_model_budget.py",
        "tests/contract/test_admission_limits.py",
    ],
    "D06": [
        "tests/unit/test_image_security.py",
        "tests/unit/test_builder_session_policy.py",
        "tests/unit/test_signed_build_verifier.py",
        "tests/unit/test_sbom_schema.py",
    ],
    "D07": ["tests/unit/test_security_observations.py", "tests/unit/test_security_audit.py"],
    "D08": ["tests/unit/test_database_security_review.py", "tests/contract/test_shared_database_pool.py"],
    "D09": ["tests/unit/test_adaptive_security_boundary.py"],
}


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    args.output_directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    env = dict(os.environ)
    for key in (
        "OPENAI_API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS",
    ):
        env.pop(key, None)
    env["AWS_EC2_METADATA_DISABLED"] = "true"
    results = {}
    for category, tests in CASES.items():
        start = time.monotonic()
        xml = args.output_directory / (category + ".xml")
        with (args.output_directory / (category + ".log")).open("xb") as log:
            process = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                    *tests,
                    "--junitxml=" + str(xml),
                    "-o",
                    "junit_family=legacy",
                ],
                stdout=log,
                stderr=subprocess.STDOUT,
                env=env,
                timeout=600,
                check=False,
            )
        nodes = list(ET.parse(xml).getroot().iter("testcase"))
        skipped = sum(n.find("skipped") is not None for n in nodes)
        failed = sum(n.find("failure") is not None or n.find("error") is not None for n in nodes)
        results[category] = {
            "returncode": process.returncode,
            "tests": len(nodes),
            "failed": failed,
            "skipped": skipped,
            "duration_seconds": round(time.monotonic() - start, 3),
            "sources": {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in tests},
        }
    report = {
        "version": 1,
        "categories": results,
        "live_model_evaluation": False,
        "live_model_cost_measured": False,
        "keyless_acceptance_passed": all(
            v["returncode"] == 0 and v["failed"] == 0 and v["skipped"] == 0 for v in results.values()
        ),
        "native_aws_proofs_attached_separately": True,
        "unseen_attack_immunity_claimed": False,
        "native_incident_response_percentiles_claimed": False,
    }
    (args.output_directory / "summary.json").write_text(json.dumps(report, indent=2))
    print(
        json.dumps(
            {
                "keyless_acceptance_passed": report["keyless_acceptance_passed"],
                "cases": sum(v["tests"] for v in results.values()),
            }
        )
    )
    return 0 if report["keyless_acceptance_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
