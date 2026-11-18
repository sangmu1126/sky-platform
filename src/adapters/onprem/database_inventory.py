"""Read-only ownership inspection of a pinned, persistent VM PostgreSQL container.

The transport is operator-owned and must authenticate a pinned SSH host key.
Docker administration is not a sandbox. No application source constructs these
registrations, transport arguments, labels, volume names or connection endpoints.
"""

import base64
import binascii
import hashlib
import json
import re
import shlex
from dataclasses import asdict, dataclass
from datetime import UTC
from pathlib import Path

from adapters.build.process import bounded_command
from adapters.runtime.environment_secrets import pinned_private_file
from adapters.runtime.private_network import pinned_private_address
from adapters.runtime.strict_json import strict_external_json
from domain.database_inventory import DatabaseInventoryUnavailable, DatabaseResourceEvidence
from domain.database_migration import DatabasePlacement, _reference

_CONTAINER = (
    '{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},'
    '"labels":{{json .Config.Labels}},"privileged":{{json .HostConfig.Privileged}},'
    '"network_mode":{{json .HostConfig.NetworkMode}},"mounts":{{json .Mounts}},'
    '"ports":{{json .NetworkSettings.Ports}}}'
)
_VOLUME = (
    '{"name":{{json .Name}},"driver":{{json .Driver}},"scope":{{json .Scope}},'
    '"labels":{{json .Labels}},"options":{{if .Options}}true{{else}}false{{end}}}'
)


def _pinned_ed25519_known_host(content, address, port):
    try:
        text = content.decode("ascii")
        if "\r" in text or not text.endswith("\n") or text.count("\n") != 1:
            raise ValueError
        host, algorithm, encoded = text[:-1].split(" ")
        expected_host = str(address) if port == 22 else f"[{address}]:{port}"
        if host != expected_host or algorithm != "ssh-ed25519":
            raise ValueError
        blob = base64.b64decode(encoded, validate=True)
        offset = 0
        fields = []
        for maximum in (64, 32):
            if offset + 4 > len(blob):
                raise ValueError
            size = int.from_bytes(blob[offset : offset + 4], "big")
            offset += 4
            if not 1 <= size <= maximum or offset + size > len(blob):
                raise ValueError
            fields.append(blob[offset : offset + size])
            offset += size
        if offset != len(blob) or fields[0] != b"ssh-ed25519" or len(fields[1]) != 32 or not any(fields[1]):
            raise ValueError
    except (UnicodeDecodeError, binascii.Error, ValueError):
        raise ValueError("Exact pinned Ed25519 SSH host key required") from None


class PinnedVmInventoryCommand:
    def __init__(
        self,
        *,
        host,
        user,
        port,
        private_key,
        known_hosts,
        private_key_sha256,
        known_hosts_sha256,
    ):
        try:
            address = pinned_private_address(host)
        except ValueError:
            raise ValueError("Pinned private SSH address required") from None
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
            raise ValueError("Pinned SSH host and user required")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("Pinned SSH port required")
        private_key, known_hosts = Path(private_key), Path(known_hosts)
        try:
            pinned_private_file(private_key, private_key_sha256)
            known_host = pinned_private_file(known_hosts, known_hosts_sha256)
        except ValueError:
            raise ValueError("Private key and pinned host-key file must be operator-private") from None
        _pinned_ed25519_known_host(known_host, address, port)
        self.arguments = [
            "ssh",
            "-F",
            "/dev/null",
            "-p",
            str(port),
            "-i",
            str(private_key),
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "HostKeyAlgorithms=ssh-ed25519",
            "-o",
            "UserKnownHostsFile=" + str(known_hosts),
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "VerifyHostKeyDNS=no",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ProxyCommand=none",
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "ServerAliveInterval=5",
            "-o",
            "ServerAliveCountMax=1",
            user + "@" + str(address),
        ]

    def __call__(self, arguments):
        # A fixed metadata command set; no shell scripts or arbitrary Docker calls.
        valid = (
            arguments == ["info", "--format", "{{json .ID}}"]
            or (
                len(arguments) == 4
                and arguments[:2] == ["inspect", "--format"]
                and arguments[2] == _CONTAINER
                and re.fullmatch(r"[a-f0-9]{64}", arguments[3])
            )
            or (
                len(arguments) == 5
                and arguments[:3] == ["volume", "inspect", "--format"]
                and arguments[3] == _VOLUME
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", arguments[4])
            )
        )
        if not valid:
            raise ValueError("Only registered read-only inventory commands permitted")
        code, output = bounded_command(
            [*self.arguments, shlex.join(["sudo", "-n", "docker", *arguments])],
            timeout=15,
            output_limit=65536,
        )
        if code:
            raise DatabaseInventoryUnavailable("Pinned VM inventory transport unavailable")
        return output


@dataclass(frozen=True)
class VmDatabaseInventoryRegistration:
    placement: DatabasePlacement
    daemon_id: str
    container_id: str
    image_id: str
    volume_name: str
    server_hostname: str
    server_port: int

    def __post_init__(self):
        from datetime import datetime

        if self.placement.location.provider != "onprem" or self.placement.role not in {
            "dedicated_workload",
            "existing_workload",
        }:
            raise ValueError("App-owned VM database placement required")
        if not re.fullmatch(r"[A-Za-z0-9:-]{8,128}", self.daemon_id) or not re.fullmatch(
            r"[a-f0-9]{64}", self.container_id
        ):
            raise ValueError("Immutable Docker daemon and container identities required")
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", self.image_id):
            raise ValueError("Pinned database image ID required")
        _reference(self.volume_name, "database volume")
        DatabaseResourceEvidence(
            self.placement, "registration", datetime.now(UTC), self.server_hostname, self.server_port
        )


class VmDatabaseInventoryVerifier:
    def __init__(self, registration, command, *, clock):
        if not isinstance(registration, VmDatabaseInventoryRegistration):
            raise TypeError("Operator VM database registration required")
        self.registration, self.command, self.clock = registration, command, clock

    def verify(self, placement):
        r = self.registration
        if placement != r.placement:
            raise ValueError("VM inventory differs from registration")
        try:
            daemon = strict_external_json(
                self.command(["info", "--format", "{{json .ID}}"]),
                maximum=65536,
                expected_type=str,
            )
            container = strict_external_json(
                self.command(["inspect", "--format", _CONTAINER, r.container_id]),
                maximum=65536,
                expected_type=dict,
            )
            volume = strict_external_json(
                self.command(["volume", "inspect", "--format", _VOLUME, r.volume_name]),
                maximum=65536,
                expected_type=dict,
            )
            labels = {
                "sky-managed": "true",
                "sky-organization-id": placement.organization_id,
                "sky-application-id": placement.application_id,
                "sky-owner-ref": placement.owner_ref,
                "sky-database-role": placement.role,
            }
            if (
                daemon != r.daemon_id
                or container.get("id") != r.container_id
                or container.get("image") != r.image_id
                or container.get("running") is not True
                or container.get("privileged") is not False
                or container.get("network_mode") in {"host", "none"}
                or any(container.get("labels", {}).get(k) != v for k, v in labels.items())
                or volume.get("name") != r.volume_name
                or volume.get("driver") != "local"
                or volume.get("scope") != "local"
                or volume.get("options") is not False
                or any(volume.get("labels", {}).get(k) != v for k, v in labels.items())
            ):
                raise ValueError("VM database identity or ownership changed")
            mounts = container.get("mounts", [])
            data = [m for m in mounts if m.get("Destination") == "/var/lib/postgresql/data"]
            if (
                len(data) != 1
                or data[0].get("Type") != "volume"
                or data[0].get("Name") != r.volume_name
                or data[0].get("RW") is not True
            ):
                raise ValueError("Pinned persistent database volume required")
            if any(
                m.get("Source") == "/" or m.get("Destination") in {"/var/run/docker.sock", "/run/docker.sock"}
                for m in mounts
            ):
                raise ValueError("Unsafe database mount")
            ports = container.get("ports", {}).get("5432/tcp")
            if (
                not isinstance(ports, list)
                or len(ports) != 1
                or ports[0].get("HostPort") != str(r.server_port)
                or ports[0].get("HostIp") in {None, "", "0.0.0.0", "::"}
            ):
                raise ValueError("One explicitly bound registered database port required")
            digest = hashlib.sha256(
                json.dumps(
                    {"registration": asdict(r), "daemon": daemon, "labels": labels}, sort_keys=True
                ).encode()
            ).hexdigest()
            return DatabaseResourceEvidence(
                placement, "VM-" + digest, self.clock(), r.server_hostname, r.server_port
            )
        except Exception:  # noqa: BLE001 -- never expose remote inspection diagnostics or environment
            raise DatabaseInventoryUnavailable("Registered VM inventory ownership unavailable") from None
