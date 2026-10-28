"""Inventory this trusted Python environment and query OSV without executing packages.

Never run this in a user workload environment with private package metadata.
This is Python dependency coverage, not an OS/image scan or malware attestation.
No model, AWS credentials, dynamic endpoints or vulnerability code are used.
"""

import argparse
import importlib.metadata
import json
import re
import urllib.request
from datetime import UTC, datetime
from pathlib import Path


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def inventory(distributions):
    packages = set()
    for distribution in distributions:
        name, version = distribution.metadata["Name"], distribution.version
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name)
            or not isinstance(version, str)
            or not re.fullmatch(r"[A-Za-z0-9_.+!-]{1,128}", version)
        ):
            raise ValueError("Invalid dependency identity")
        packages.add((re.sub(r"[-_.]+", "-", name).lower(), version))
    if not 1 <= len(packages) <= 200:
        raise ValueError("Bounded trusted environment required")
    return [{"name": name, "version": version} for name, version in sorted(packages)]


def query(packages):
    request = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        method="POST",
        data=json.dumps(
            {
                "queries": [
                    {"package": {"name": item["name"], "ecosystem": "PyPI"}, "version": item["version"]}
                    for item in packages
                ]
            }
        ).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "Sky-Dependency-Audit/1"},
    )
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
        raw = response.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("Vulnerability response exceeds bound")
    result = json.loads(raw)
    if (
        not isinstance(result, dict)
        or not isinstance(result.get("results"), list)
        or len(result["results"]) != len(packages)
    ):
        raise ValueError("Vulnerability response is incomplete")
    findings = []
    for package, item in zip(packages, result["results"]):
        if (
            not isinstance(item, dict)
            or set(item) - {"vulns", "next_page_token"}
            or item.get("next_page_token")
        ):
            raise ValueError("Vulnerability response requires reconciliation")
        vulnerabilities = item.get("vulns", [])
        if not isinstance(vulnerabilities, list):
            raise ValueError("Invalid vulnerability result")  # noqa: TRY004 -- invalid provider contract
        ids = []
        for vulnerability in vulnerabilities:
            if (
                not isinstance(vulnerability, dict)
                or not isinstance(vulnerability.get("id"), str)
                or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", vulnerability["id"])
            ):
                raise ValueError("Invalid vulnerability identity")
            ids.append(vulnerability["id"])
        if ids:
            findings.append({**package, "vulnerabilities": sorted(set(ids))})
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    packages = inventory(importlib.metadata.distributions())
    report = {
        "schema_version": 1,
        "observed_at": datetime.now(UTC).isoformat(),
        "scope": "trusted-installed-python-environment-only",
        "packages": packages,
        "os_image_scanned": False,
        "malware_absence_proven": False,
    }
    try:
        report["findings"] = query(packages)
        report["status"] = (
            "vulnerabilities_found" if report["findings"] else "no_known_vulnerabilities_returned"
        )
    except (ValueError, OSError):
        report["status"] = "unverified_feed_unavailable_or_invalid"
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "package_count": len(packages)}))
    return 0 if report["status"] == "no_known_vulnerabilities_returned" else 1


if __name__ == "__main__":
    raise SystemExit(main())
