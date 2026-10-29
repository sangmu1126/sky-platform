"""Read fixed operator-pinned bootstrap data; never execute it in this process."""

import hashlib
import json
import os
from pathlib import Path

from scripts.builder_session_policy import policy


def main():
    import boto3

    policy("controller", os.environ)
    manifest = json.loads(os.environ["SKY_TRUSTED_BUILD_MATERIALS_JSON"])
    if not isinstance(manifest, dict) or set(manifest) != {"base.tar", "trivy", "scanner-db.tar.gz"}:
        raise ValueError("Three pinned offline build/scan materials required")
    root = Path("trusted-build-materials")
    root.mkdir(mode=0o700, exist_ok=False)
    client = boto3.client("s3", region_name=os.environ["AWS_REGION"])
    for name, expected in manifest.items():
        import re

        if not isinstance(expected, str) or not re.fullmatch("[a-f0-9]{64}", expected):
            raise ValueError("Pinned material SHA-256 required")
        response = client.get_object(
            Bucket=os.environ["SKY_ARTIFACTS_BUCKET"],
            Key=os.environ["SKY_TRUSTED_BUILD_MATERIALS_PREFIX"] + "/" + name,
            ExpectedBucketOwner=os.environ["SKY_AWS_ACCOUNT_ID"],
        )
        digest = hashlib.sha256()
        size = 0
        body = response["Body"]
        try:
            with (root / name).open("xb") as target:
                while chunk := body.read(1024 * 1024):
                    size += len(chunk)
                    if size > 1024**3:
                        raise ValueError("Bootstrap material exceeds bound")
                    target.write(chunk)
                    digest.update(chunk)
        finally:
            body.close()
        if digest.hexdigest() != expected:
            raise ValueError("Bootstrap material changed; no VM/source execution permitted")
    with open(os.environ["GITHUB_ENV"], "a") as out:
        for variable, name in (
            ("SKY_OFFLINE_BUILD_BASE_ARCHIVE", "base.tar"),
            ("SKY_OFFLINE_SCANNER_BINARY", "trivy"),
            ("SKY_OFFLINE_SCANNER_DATABASE", "scanner-db.tar.gz"),
        ):
            out.write(variable + "=" + str((root / name).resolve()) + "\n")
        out.write("SKY_OFFLINE_BUILD_BASE_ARCHIVE_SHA256=" + manifest["base.tar"] + "\n")
        out.write("SKY_OFFLINE_SCANNER_DATABASE_SHA256=" + manifest["scanner-db.tar.gz"] + "\n")


if __name__ == "__main__":
    main()
