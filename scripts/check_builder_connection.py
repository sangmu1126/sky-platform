"""Read-only check against the shipped personal-builder reference contract.

Run python -m scripts.check_builder_connection [--github] with SKY_BUILDER_*,
SKY_ARTIFACTS_BUCKET, SKY_AWS_ACCOUNT_ID and SKY_AWS_REGION configured.
--github uses the existing gh login for GET requests only, never dispatches or
accesses AWS. Exact file comparisons deliberately reject customized workflows;
a mismatch calls for review and is not proof that a custom workflow is unsafe.
This does not establish IAM/OIDC, GitHub App, S3 or ECR runtime readiness.
"""

import argparse
import base64
import json
import os
import subprocess
import urllib.parse
from pathlib import Path

from ports.remote_builds import BuildSettings

ROOT = Path(__file__).resolve().parents[1]


class ReferenceMismatch(ValueError):
    """A fixed diagnostic safe to display without remote response data."""


def github_get(path):
    result = subprocess.run(
        ["gh", "api", "--method", "GET", path],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode:
        raise OSError("GitHub read unavailable; check repository visibility and read permissions")
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise TypeError("Expected GitHub object response")
    return value


def file_bytes(document):
    if document.get("type") != "file" or document.get("encoding") != "base64":
        raise ValueError("Expected a readable GitHub file")
    return base64.b64decode("".join(document["content"].split()), validate=True)


def check_reference(settings, get=github_get):
    base = "/repos/" + settings.repository
    ref = urllib.parse.quote(settings.ref, safe="")
    if get(base + "/commits/" + ref).get("sha") != settings.workflow_sha:
        raise ReferenceMismatch("Builder ref differs from pinned workflow commit")
    workflow = file_bytes(
        get(base + "/contents/.github/workflows/" + settings.workflow + "?ref=" + settings.workflow_sha)
    )
    if workflow != (ROOT / "ops/remote-builder/build.yml").read_bytes():
        raise ReferenceMismatch("Pinned workflow differs from the reviewed personal-builder template")
    variable = get(base + "/actions/variables/SKY_PLATFORM_CODE_SHA")
    if variable.get("value") != settings.platform_code_sha:
        raise ReferenceMismatch("Builder platform-code variable differs from configured pin")
    code = file_bytes(
        get(
            "/repos/sangmu1126/sky-platform/contents/scripts/remote_builder.py?ref="
            + settings.platform_code_sha
        )
    )
    if code != (ROOT / "scripts/remote_builder.py").read_bytes():
        raise ReferenceMismatch("Pinned platform builder code differs from this tested implementation")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--github", action="store_true", help="Also check GitHub with read-only gh API calls")
    args = parser.parse_args(argv)
    stage = "configuration"
    try:
        settings = BuildSettings.from_environment(os.environ)
        if args.github:
            stage = "github_reference"
            check_reference(settings)
    except (ValueError, TypeError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        # Do not echo raw API responses, subprocess stderr or environment values.
        print(
            json.dumps(
                {
                    "status": "check_failed",
                    "stage": stage,
                    "reason": str(error)
                    if isinstance(error, ReferenceMismatch)
                    else "Configuration or GitHub read unavailable",
                    "github_checked": args.github,
                    "next": "Review builder configuration, visibility, pins and reference-template compatibility",
                }
            )
        )
        return 1
    print(
        json.dumps(
            {
                "status": "reference_matches" if args.github else "configuration_valid",
                "github_checked": args.github,
                "runtime_verified": False,
                "remaining": [
                    "IAM/OIDC trust",
                    "GitHub App installation",
                    "AWS artifact scope",
                    "actual ECR publish",
                ],
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
