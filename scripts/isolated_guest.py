"""Trusted stdlib-only guest entry point. Executed ONLY in a disposable VM.

Upload as build.py alongside offline.py. No AWS/GitHub/model library or secret.
The guest must already be sealed by the registered control plane before transfer.
"""

import json
import os
import re
import tarfile
import time
from pathlib import Path, PurePosixPath

from offline import validate_offline_dockerfile
from process import bounded_command

STAGE = "initialization"

ROOT = Path("/home/ec2-user")


def command(args):
    code, text = bounded_command(args, timeout=300, output_limit=8 * 1024**2)
    if code:
        raise OSError("Isolated guest command failed")
    return text


def rehearse(image, identity, settings):
    # No credentials, socket, host mounts, published port or outbound network.
    if settings["target_verification_required"]:
        return {"image_id": identity, "status": "requires_target_verification", "credentials_used": False}
    port, path = settings["port"], settings["health_path"]
    if (
        type(port) is not int
        or not 1024 <= port <= 65535
        or not re.fullmatch(r"/[A-Za-z0-9/_.-]*", path)
        or ".." in path
        or "//" in path
    ):
        raise ValueError("Fixed loopback health probe required")
    container = command(
        [
            "docker",
            "run",
            "-d",
            "--network",
            "none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user",
            "65534:65534",
            "--pids-limit",
            "64",
            "--memory",
            "128m",
            "--cpus",
            "1",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "--env",
            "PORT=" + str(port),
            image,
        ]
    ).strip()
    if not re.fullmatch("[a-f0-9]{64}", container):
        raise ValueError("Observed rehearsal container required")
    try:
        pid = command(["docker", "inspect", "--format", "{{.State.Pid}}", container]).strip()
        if not pid.isdigit() or int(pid) < 2:
            raise ValueError("Running isolated rehearsal process required")
        probe = (
            "import urllib.request,hashlib,json; "
            "h=type('NoRedirect',(urllib.request.HTTPRedirectHandler,),{'redirect_request':lambda *a,**k:None}); "
            "o=urllib.request.build_opener(urllib.request.ProxyHandler({}),h); "
            "r=o.open('http://127.0.0.1:" + str(port) + path + "',timeout=2); "
            "b=r.read(1048577); "
            "assert r.status==200 and len(b)<=1048576; "
            "print(json.dumps({'status_code':r.status,'body_sha256':hashlib.sha256(b).hexdigest()}))"
        )
        until = time.monotonic() + 20
        while True:
            code, text = bounded_command(
                ["nsenter", "--target", pid, "--net", "--", "/usr/bin/python3", "-c", probe],
                timeout=3,
                output_limit=8192,
            )
            if code == 0:
                observed = json.loads(text)
                return {
                    "image_id": identity,
                    "status": "http_verified",
                    "credentials_used": False,
                    **observed,
                }
            if time.monotonic() >= until:
                raise OSError("Isolated HTTP rehearsal failed; target verification not inferred")
            time.sleep(1)
    finally:
        command(["docker", "rm", "-f", container])


def main():
    global STAGE
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
    STAGE = "building"
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
    STAGE = "rehearsal"
    rehearsal = rehearse(image, identity, settings)
    (ROOT / "rehearsal.json").write_text(json.dumps(rehearsal))
    STAGE = "archive_export"
    command(["docker", "save", "-o", str(ROOT / "image.tar"), image])
    (ROOT / "image-id.txt").write_text(identity)
    os.chmod(ROOT / "image.tar", 0o644)
    print(json.dumps({"built": True, "image_id": identity, "network": "none", "credentials_in_guest": False}))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # noqa: BLE001 -- no raw source, app response or command logs
        print(json.dumps({"build_failure_stage": STAGE, "error_type": type(error).__name__}))
        raise SystemExit(1) from None
