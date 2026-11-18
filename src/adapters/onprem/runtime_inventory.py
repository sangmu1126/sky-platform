"""Pinned SSH transport for the fixed read-only Linux runtime helper."""

import hashlib
import json
import os
import re
import shlex
import stat
from pathlib import Path

from adapters.build.process import bounded_command
from adapters.runtime.workload_inventory import RegisteredLinuxRuntimeInventory
from ports.workload_inventory import WorkloadInventoryUnavailable

RUNTIME_HELPER_PATH = "/usr/local/bin/sky-runtime-inventory-helper"


def _remote_identity(host, user, port):
    if not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host):
        raise ValueError("Pinned runtime SSH host required")
    if not isinstance(user, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
        raise ValueError("Pinned runtime SSH user required")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Pinned runtime SSH port required")


def _operator_file(path):
    value = Path(path)
    if not value.is_absolute():
        raise ValueError("Absolute operator SSH identity file required")
    descriptor = os.open(value, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
            raise ValueError("Operator-private SSH key and known-hosts files required")
        data = bytearray()
        while len(data) <= 1024 * 1024:
            chunk = os.read(descriptor, min(65536, 1024 * 1024 + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
    finally:
        os.close(descriptor)
    if not data or len(data) > 1024 * 1024:
        raise ValueError("Bounded SSH identity file required")
    return value, hashlib.sha256(data).hexdigest()


def remote_runtime_authority_ref(host, user, port, known_hosts):
    """Bind runtime registration to one host/user/port and exact host-key file."""
    _remote_identity(host, user, port)
    _path, known_hosts_sha256 = _operator_file(known_hosts)
    value = json.dumps(
        {
            "host": host,
            "user": user,
            "port": port,
            "known_hosts_sha256": known_hosts_sha256,
            "helper": RUNTIME_HELPER_PATH,
            "protocol": "json-v1",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return "ssh-" + hashlib.sha256(value).hexdigest()


class PinnedVmRuntimeObservationTransport:
    def __init__(self, *, host, user, port, private_key, known_hosts, guard):
        _remote_identity(host, user, port)
        if not callable(guard):
            raise TypeError("Current remote runtime guard required")
        key, key_sha256 = _operator_file(private_key)
        hosts, hosts_sha256 = _operator_file(known_hosts)
        self.host, self.user, self.port = host, user, port
        self.private_key, self.known_hosts = key, hosts
        self.key_sha256, self.hosts_sha256 = key_sha256, hosts_sha256
        self.authority_ref = remote_runtime_authority_ref(host, user, port, hosts)
        self.guard = guard
        self.arguments = [
            "ssh",
            "-F",
            "/dev/null",
            "-T",
            "-p",
            str(port),
            "-i",
            str(key),
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UserKnownHostsFile=" + str(hosts),
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "RequestTTY=no",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "ServerAliveInterval=5",
            "-o",
            "ServerAliveCountMax=1",
            user + "@" + host,
        ]

    def _unchanged(self):
        return (
            _operator_file(self.private_key)[1] == self.key_sha256
            and _operator_file(self.known_hosts)[1] == self.hosts_sha256
        )

    def observe(self, registration):
        if not isinstance(registration, RegisteredLinuxRuntimeInventory):
            raise TypeError("Registered Linux runtime inventory required")
        document = registration.document()
        registration_id = document["runtime_registration_id"]
        if registration.authority_ref != self.authority_ref or not re.fullmatch(
            r"WRR-[a-f0-9]{64}", registration_id
        ):
            raise ValueError("Remote runtime authority differs from registration")
        try:
            if not self._unchanged():
                raise ValueError("SSH identity files changed")
            self.guard()
            command = shlex.join(
                [
                    "sudo",
                    "-n",
                    RUNTIME_HELPER_PATH,
                    "--registration",
                    registration_id,
                    "--format",
                    "json-v1",
                ]
            )
            code, output = bounded_command(
                [*self.arguments, command],
                timeout=15,
                output_limit=512 * 1024,
            )
            self.guard()
            if code or not self._unchanged():
                raise OSError("Pinned runtime helper unavailable")
            observation = json.loads(output)
            if observation.get("runtime_registration_id") != registration_id:
                raise ValueError("Remote helper returned another registration")
            return observation
        except Exception:  # noqa: BLE001 -- SSH and remote helper diagnostics stay private
            raise WorkloadInventoryUnavailable("Pinned VM runtime observation unavailable") from None
