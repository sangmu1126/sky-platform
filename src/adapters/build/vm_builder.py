"""Credential-free execution orchestration; cloud credentials stay in the controller."""

import hashlib
import json
import math
import os
import subprocess
import sys
import tarfile
import tempfile
import time
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path, PurePosixPath
from uuid import UUID, uuid4

from adapters.aws.build_sandbox import AwsBuildSandbox
from adapters.build.image import ImageBuilder
from adapters.build.saved_archive import validate_saved_archive
from adapters.build.ssh_guest import SealedGuest
from application.deployment_core import ignored_source_path


def pack_context(context, destination):
    total, count = 0, 0
    with tarfile.open(destination, "w", format=tarfile.USTAR_FORMAT) as archive:
        for path in sorted(context.rglob("*")):
            if ignored_source_path(PurePosixPath(path.relative_to(context).as_posix())):
                continue
            if path.is_symlink():
                raise ValueError("Isolated context cannot contain symbolic links")
            if path.is_dir():
                continue
            if not path.is_file():
                raise ValueError("Isolated context contains a special file")
            info = path.stat()
            total += info.st_size
            count += 1
            if total > 100 * 1024**2 or count > 10000:
                raise ValueError("Isolated source context exceeds bounds")
            member = tarfile.TarInfo(path.relative_to(context).as_posix())
            member.size = info.st_size
            member.mode = 0o755 if info.st_mode & 0o111 else 0o644
            with path.open("rb") as source:
                archive.addfile(member, source)


class IsolatedVmBuilder:
    def __init__(self, profile, session, guard, event, *, audit):
        if not callable(audit) or not callable(guard):
            raise ValueError("Trusted durable audit and current execution guard required")
        self.profile, self.session = profile, session
        self.sandbox = AwsBuildSandbox(profile, session, guard)
        self.guard, self.event, self.audit = guard, event, audit

    def build(self, project, plan, output, *, base_archive, bases, extra_ca_bundle=None, build_id=None):
        if not isinstance(bases, dict) or len(bases) != 1:
            raise ValueError("One pinned offline base archive is required by this profile")
        base_tag, base_id = next(iter(bases.items()))
        validate_saved_archive(base_archive, base_id, base_tag)
        output = Path(output)
        if not output.is_dir() or any(output.iterdir()):
            raise ValueError("Empty operator-owned build output directory required")
        job = str(uuid4()) if build_id is None else build_id
        image_tag = "sky-build:" + job
        self.audit(
            {
                "stage": "build_admitted",
                "job_id": job,
                "source_digest": plan.source_digest,
                "profile": self.sandbox.profile.name,
                "source_executed_in_controller": False,
            }
        )
        with ImageBuilder(None, self.event).prepare(project, plan, extra_ca_bundle) as context:
            with tempfile.TemporaryDirectory(prefix="sky-vm-controller-") as temporary:
                root = Path(temporary)
                pack_context(context, root / "context.tar")
                (root / "bases.json").write_text(
                    json.dumps(
                        {
                            "bases": bases,
                            "image_tag": image_tag,
                            "port": plan.port,
                            "health_path": plan.health_path,
                            "target_verification_required": bool(plan.required_env or extra_ca_bundle),
                        }
                    )
                )
                with self.guest(job, root) as (guest, receipt):
                    trusted = Path(__file__).resolve().parents[3]
                    for source, name in (
                        (base_archive, "base.tar"),
                        (root / "context.tar", "context.tar"),
                        (root / "bases.json", "bases.json"),
                        (trusted / "scripts/isolated_guest.py", "build.py"),
                        (Path(__file__).with_name("offline.py"), "offline.py"),
                        (Path(__file__).with_name("process.py"), "process.py"),
                    ):
                        guest.upload(source, name)
                    self.event("building", "Building in an isolated credential-free VM")
                    guest.build()
                    guest.download("rehearsal.json", output / "rehearsal.json", limit=8192)
                    guest.download("image-id.txt", output / "image-id.txt", limit=128)
                    guest.download("image.tar", output / "image.tar", limit=4 * 1024**3)
                    image_id = (output / "image-id.txt").read_text().strip()
                    proof = validate_saved_archive(output / "image.tar", image_id, image_tag)
                    self.audit(
                        {
                            "stage": "image_received",
                            "job_id": job,
                            "config_digest": image_id,
                            "archive_bytes": proof["archive_bytes"],
                            "code_executed_in_controller": False,
                        }
                    )
                    result = {
                        "image_id": image_id,
                        "local_tag": image_tag,
                        "sandbox_job_id": job,
                        "archive": str(output / "image.tar"),
                        "expires_at": receipt["expires_at"],
                    }
                from adapters.build.image_security import sha
                from ports.remote_builds import canonical

                (output / "materials.json").write_bytes(
                    canonical(
                        {
                            "base_archive_sha256": sha(base_archive),
                            "context_sha256": sha(root / "context.tar"),
                            "profile_sha256": hashlib.sha256(
                                canonical(asdict(self.sandbox.profile))
                            ).hexdigest(),
                            "build_vm_job": job,
                            "scanner_vm_job": None,
                        }
                    )
                )
                (output / "usage.json").write_bytes(
                    canonical(
                        {
                            "build_seconds": receipt["observed_seconds"],
                            "source": "trusted_controller_elapsed_upper",
                            "cost_measured": False,
                            "reservation_released": False,
                        }
                    )
                )
                return result

    @contextmanager
    def guest(self, job, root):
        """One sealed VM per stage; scanner never reuses the build execution VM."""
        if not isinstance(job, str) or str(UUID(job)) != job:
            raise ValueError("Canonical trusted build identity required")
        from adapters.aws.build_controller_session import controller_session

        self.sandbox = AwsBuildSandbox(
            self.profile, controller_session(self.profile, self.session, job), self.guard
        )
        receipt = None
        key = root / "key"
        subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "sky-build-control",
                "-f",
                str(key),
            ],
            check=True,
            timeout=15,
            stdout=subprocess.DEVNULL,
        )
        self.guard()
        started = time.monotonic()
        try:
            receipt = self.sandbox.launch(job, key.with_suffix(".pub").read_text())
            self.audit({"stage": "guest_launched", **receipt})
            deadline = time.monotonic() + 120
            while True:
                self.guard()
                host_key = self.sandbox.host_key(receipt)
                if host_key:
                    break
                if time.monotonic() >= deadline:
                    raise OSError("Trusted guest boot exceeded deadline")
                time.sleep(3)
            self.sandbox.seal(receipt)
            while True:
                instance = self.sandbox.inspect(receipt, bootstrapping=True)
                if (
                    instance["MetadataOptions"].get("HttpEndpoint") == "disabled"
                    and instance["MetadataOptions"].get("State") == "applied"
                ):
                    break
                self.guard()
                if time.monotonic() >= deadline:
                    raise OSError("Guest metadata sealing exceeded deadline")
                time.sleep(1)
            self.sandbox.profile.verify_network(self.sandbox.ec2)
            known = root / "known_hosts"
            known.write_text(instance["PublicIpAddress"] + " " + host_key + "\n")
            os.chmod(known, 0o600)
            guest = SealedGuest(self.sandbox, receipt, key, known)
            self.audit(
                {
                    "stage": "guest_sealed",
                    "job_id": job,
                    "metadata": "disabled",
                    "credentials_in_guest": False,
                    "outbound_rules": 0,
                }
            )
            yield guest, receipt
        finally:
            failed = sys.exc_info()[0] is not None
            if receipt is not None:
                # Cleanup may run after a user lease is revoked: use the
                # dedicated external reaper, never widen execution rights.
                try:
                    self.sandbox.terminate(receipt)
                    until = time.monotonic() + 60
                    while self.sandbox.inspect(receipt, bootstrapping=True)["State"]["Name"] != "terminated":
                        if time.monotonic() >= until:
                            raise OSError("Termination remains pending")
                        time.sleep(2)
                    self.sandbox.finalize(receipt)
                    receipt["observed_seconds"] = max(1, math.ceil(time.monotonic() - started))
                    self.audit({"stage": "guest_terminated", "job_id": job, "confirmed": True})
                except Exception:
                    self.audit(
                        {
                            "stage": "cleanup_requires_reconciliation",
                            "job_id": job,
                            "external_deadline": receipt["expires_at"],
                            "confirmed": False,
                        }
                    )
                    if not failed:
                        raise OSError("Guest termination unconfirmed; reconcile before publication") from None
