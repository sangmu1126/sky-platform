"""CI-only check of a trusted synthetic fixture transferred between fresh jobs.

No AWS clients or registry login. This is not a general user-image runner.
"""

import json
import os
import subprocess
from pathlib import Path

from ports.remote_builds import validate_request
from scripts.remote_builder import command, verified_build


def main():
    directory = Path(os.environ["SKY_TEST_BUILD_EXPORT_DIR"])
    request = json.loads((directory / "request.json").read_bytes())
    validate_request(request)
    if (
        request["repository"] != os.environ["GITHUB_REPOSITORY"]
        or request["workflow_sha"] != os.environ["GITHUB_SHA"]
        or request["platform_code_sha"] != os.environ["GITHUB_SHA"]
    ):
        raise ValueError("Fixture workflow provenance mismatch")
    image_id = verified_build(request, directory / "output")
    tag = "sky-build:" + request["build_id"]
    try:
        command(["docker", "load", "-i", str(directory / "output/image.tar")])
        if command(["docker", "image", "inspect", "--format", "{{.Id}}", tag]).strip() != image_id:
            raise ValueError("Transferred image identity mismatch")
        if (
            command(["docker", "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", image_id]).strip()
            != "linux/amd64"
        ):
            raise ValueError("Transferred image architecture mismatch")
        result = command(
            [
                "docker",
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                image_id,
            ],
            timeout=20,
        )
        if result.strip() != "verified-build-fixture":
            raise ValueError("Unexpected synthetic fixture output")
        print("PASS: transferred request, archive, image ID and actual fixture execution agree")
    finally:
        subprocess.run(["docker", "image", "rm", tag], check=False, capture_output=True, timeout=30)


if __name__ == "__main__":
    main()
