"""Pinned SSH data transport to an already sealed disposable build VM only."""

import os
import re
import signal
import subprocess
import time
from pathlib import Path

from adapters.build.process import bounded_command


class SealedGuest:
    def __init__(self, sandbox, receipt, private_key, known_hosts):
        self.sandbox, self.receipt = sandbox, receipt
        instance = sandbox.inspect(receipt)
        self.host = instance.get("PublicIpAddress")
        if not isinstance(self.host, str) or not re.fullmatch(r"[0-9.]{7,15}", self.host):
            raise ValueError("Observed guest IPv4 address required")
        if instance["State"]["Name"] != "running":
            raise ValueError("Sealed guest must be running")
        for path in (private_key, known_hosts):
            if Path(path).is_symlink() or not Path(path).is_file() or Path(path).stat().st_mode & 0o077:
                raise ValueError("Operator-private SSH key and pinned known-hosts files required")
        self.options = [
            "-i",
            str(private_key),
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UserKnownHostsFile=" + str(known_hosts),
            "-o",
            "ForwardAgent=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ServerAliveInterval=10",
            "-o",
            "ServerAliveCountMax=2",
        ]

    def guard(self):
        instance = self.sandbox.inspect(self.receipt)
        from datetime import UTC, datetime

        if instance["State"]["Name"] != "running" or datetime.now(UTC) >= datetime.fromisoformat(
            self.receipt["expires_at"]
        ):
            raise ValueError("Guest lifetime or execution boundary expired")

    def upload(self, source, name):
        if name not in {"base.tar", "context.tar", "build.py", "offline.py", "process.py", "bases.json"}:
            raise ValueError("Fixed guest input name required")
        self.guard()
        code, _ = bounded_command(
            ["scp", *self.options, str(source), f"ec2-user@{self.host}:/home/ec2-user/{name}"], timeout=120
        )
        self.guard()
        if code:
            raise OSError("Guest data upload failed")

    def build(self):
        self.guard()
        # This exact trusted script name is never supplied by application source.
        code, output = bounded_command(
            ["ssh", *self.options, "ec2-user@" + self.host, "sudo python3 /home/ec2-user/build.py"],
            timeout=600,
        )
        self.guard()
        if code:
            raise OSError("Isolated build failed; inspect the private bounded build receipt")
        return output

    def download(self, name, destination, *, limit):
        if (
            name not in {"image.tar", "image-id.txt"}
            or type(limit) is not int
            or not 1 <= limit <= 4 * 1024**3
        ):
            raise ValueError("Fixed bounded guest result required")
        self.guard()
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        process = subprocess.Popen(
            ["ssh", *self.options, "ec2-user@" + self.host, "cat /home/ec2-user/" + name],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        import selectors

        deadline, count = time.monotonic() + 120, 0
        last_guard = 0.0
        try:
            with os.fdopen(descriptor, "wb") as target, selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    if time.monotonic() >= deadline:
                        raise OSError("Guest result download exceeded time bound")
                    if time.monotonic() - last_guard >= 1:
                        self.guard()
                        last_guard = time.monotonic()
                    if not selector.select(timeout=1):
                        continue
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    count += len(chunk)
                    if count > limit:
                        raise ValueError("Guest result exceeds bounded archive size")
                    target.write(chunk)
                if process.wait(timeout=10):
                    raise OSError("Guest result transfer failed")
                target.flush()
                os.fsync(target.fileno())
            self.guard()
        except BaseException:
            Path(destination).unlink(missing_ok=True)
            raise
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
            process.stdout.close()
