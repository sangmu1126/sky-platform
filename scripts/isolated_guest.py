"""Trusted stdlib-only guest entry point. Executed ONLY in a disposable VM.

Upload as build.py alongside offline.py. No AWS/GitHub/model library or secret.
The guest must already be sealed by the registered control plane before transfer.
"""

import json
import os
import re
import tarfile
from pathlib import Path, PurePosixPath

from offline import validate_offline_dockerfile
from process import bounded_command

ROOT = Path("/home/ec2-user")


def command(args):
    code, text = bounded_command(args, timeout=300, output_limit=8 * 1024**2)
    if code:
        raise OSError("Isolated guest command failed")
    return text


def main():
    if any(
        os.environ.get(k)
        for k in (
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "OPENAI_API_KEY",
        )
    ):
        raise ValueError("Guest must have no provider or model credentials")
    # Base data may be parsed by Docker only inside this isolated, role-free VM.
    command(["docker", "load", "-i", str(ROOT / "base.tar")])
    settings = json.loads((ROOT / "bases.json").read_bytes())
    bases, image = settings["bases"], settings["image_tag"]
    if not re.fullmatch(r"sky-build:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", image):
        raise ValueError("Pinned build image tag required")
    context = ROOT / "context"
    context.mkdir(mode=0o700)
    with tarfile.open(ROOT / "context.tar", mode="r:") as archive:
        members = archive.getmembers()
        if len(members) > 10000 or sum(m.size for m in members) > 100 * 1024**2:
            raise ValueError("Bounded source context required")
        for member in members:
            path = PurePosixPath(member.name)
            if (
                not member.isfile()
                or path.is_absolute()
                or ".." in path.parts
                or "\\" in member.name
                or path.as_posix() != member.name
            ):
                raise ValueError("Regular source files only")
        archive.extractall(context, members=members, filter="data")
    validate_offline_dockerfile((context / "Dockerfile").read_text(), bases, command)
    command(
        [
            "docker",
            "build",
            "--network",
            "none",
            "--pull=false",
            "--label",
            "app=sky",
            "-t",
            image,
            str(context),
        ]
    )
    identity = command(["docker", "image", "inspect", "--format", "{{.Id}}", image]).strip()
    command(["docker", "save", "-o", str(ROOT / "image.tar"), image])
    (ROOT / "image-id.txt").write_text(identity)
    os.chmod(ROOT / "image.tar", 0o644)
    print(json.dumps({"built": True, "image_id": identity, "network": "none", "credentials_in_guest": False}))


if __name__ == "__main__":
    main()
