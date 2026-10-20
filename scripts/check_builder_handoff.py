"""CI-only check of a trusted synthetic fixture transferred between fresh jobs.

No AWS clients or registry login. This is not a general user-image runner.
"""

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from uuid import uuid4

from ports.image_manifests import MANIFEST_TYPES, verify_image_manifest
from ports.remote_builds import validate_request
from scripts.remote_builder import command, verified_build


def registry_roundtrip(image_id):
    """Publish only the trusted fixture to an ephemeral loopback registry."""
    name = "sky-manifest-check-" + uuid4().hex
    destination = None
    try:
        command(["docker", "run", "-d", "--name", name, "-p", "127.0.0.1::5000", "registry:2.8.3"])
        address = command(["docker", "port", name, "5000/tcp"]).strip()
        host, port = address.rsplit(":", 1)
        if host != "127.0.0.1" or not 1 <= int(port) <= 65535:
            raise ValueError("Unexpected fixture registry binding")
        # Ignore proxy variables; registry traffic must remain on loopback.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for attempt in range(30):
            try:
                with opener.open("http://" + address + "/v2/", timeout=2) as response:
                    if response.status == 200:
                        break
            except (OSError, urllib.error.URLError):
                if attempt == 29:
                    raise
            time.sleep(0.2)
        else:
            raise OSError("Fixture registry unavailable")
        destination = address + "/fixture:verified"
        command(["docker", "tag", image_id, destination])
        command(["docker", "push", destination], timeout=120)
        request = urllib.request.Request(
            "http://" + address + "/v2/fixture/manifests/verified",
            headers={"Accept": ", ".join(MANIFEST_TYPES)},
        )
        with opener.open(request, timeout=10) as response:
            manifest = response.read(4 * 1024 * 1024 + 1)
            image_digest = response.headers["Docker-Content-Digest"]
        verify_image_manifest(manifest, image_digest, image_id)
        print("PASS: actual registry push manifest digest and built image config ID agree")
    finally:
        if destination:
            subprocess.run(
                ["docker", "image", "rm", destination], check=False, capture_output=True, timeout=30
            )
        subprocess.run(["docker", "rm", "-f", "-v", name], check=False, capture_output=True, timeout=30)


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
        registry_roundtrip(image_id)
    finally:
        subprocess.run(["docker", "image", "rm", tag], check=False, capture_output=True, timeout=30)


if __name__ == "__main__":
    main()
