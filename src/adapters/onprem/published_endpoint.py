"""Resolve changing loopback ports through an immutable pinned Docker identity.

Port discovery is not adoption: exact daemon/container/image/owner/network must
match first. SQL/HTTP TLS, logical ownership and runtime policy remain separate
caller checks. No free SSH/Docker command or externally provided endpoint exists.
"""

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from adapters.onprem.database_inventory import _CONTAINER
from domain.environment_transition import _ref, _time


@dataclass(frozen=True)
class PinnedPublishedEndpointRegistration:
    daemon_id: str
    container_id: str
    image_id: str
    organization_id: str
    application_id: str
    owner_ref: str
    validation_run: str
    network_name: str
    container_port: int
    additional_container_ports: tuple[int, ...] = ()

    def __post_init__(self):
        if (
            not re.fullmatch(r"[A-Za-z0-9:-]{8,128}", self.daemon_id)
            or not re.fullmatch(r"[a-f0-9]{64}", self.container_id)
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", self.image_id)
        ):
            raise ValueError("Pinned Docker identity required")
        for value in (
            self.organization_id,
            self.application_id,
            self.owner_ref,
            self.validation_run,
            self.network_name,
        ):
            _ref(value)
        if type(self.container_port) is not int or not 1 <= self.container_port <= 65535:
            raise ValueError("Explicit container service port required")
        ports = self.additional_container_ports
        if (
            not isinstance(ports, tuple)
            or len(ports) > 3
            or len(set(ports)) != len(ports)
            or self.container_port in ports
            or any(type(p) is not int or not 1 <= p <= 65535 for p in ports)
        ):
            raise ValueError("Explicit distinct additional private service ports required")


@dataclass(frozen=True)
class ResolvedPublishedEndpoint:
    container_id: str
    container_port: int
    host_port: int
    observed_at: datetime
    host_address: str = "127.0.0.1"


class PinnedPublishedEndpointResolver:
    def __init__(self, registration, command, *, clock=lambda: datetime.now(UTC)):
        if not isinstance(registration, PinnedPublishedEndpointRegistration) or not callable(command):
            raise TypeError("Registered endpoint and pinned metadata command required")
        self.registration, self.command, self.clock = registration, command, clock

    def resolve(self, *, guard):
        guard()
        r = self.registration
        daemon = json.loads(self.command(["info", "--format", "{{json .ID}}"]))
        guard()
        container = json.loads(self.command(["inspect", "--format", _CONTAINER, r.container_id]))
        if not isinstance(container, dict) or daemon != r.daemon_id:
            raise ValueError("Registered Docker authority changed")
        labels = container.get("labels")
        expected = {
            "sky-managed": "true",
            "sky-organization-id": r.organization_id,
            "sky-application-id": r.application_id,
            "sky-owner-ref": r.owner_ref,
            "sky.validation": r.validation_run,
        }
        if (
            container.get("id") != r.container_id
            or container.get("image") != r.image_id
            or container.get("running") is not True
            or container.get("privileged") is not False
            or container.get("network_mode") != r.network_name
            or not isinstance(labels, dict)
            or any(labels.get(key) != value for key, value in expected.items())
        ):
            raise ValueError("Container ownership or runtime changed before port resolution")
        ports = container.get("ports")
        key = str(r.container_port) + "/tcp"
        expected_ports = {str(p) + "/tcp" for p in (r.container_port, *r.additional_container_ports)}
        if not isinstance(ports, dict) or {name for name, value in ports.items() if value} != expected_ports:
            raise ValueError("Only the registered published service is allowed")
        for name in expected_ports:
            items = ports[name]
            if (
                not isinstance(items, list)
                or len(items) != 1
                or not isinstance(items[0], dict)
                or items[0].get("HostIp") != "127.0.0.1"
                or not isinstance(items[0].get("HostPort"), str)
                or not re.fullmatch(r"[1-9][0-9]{0,4}", items[0]["HostPort"])
                or not 1 <= int(items[0]["HostPort"]) <= 65535
            ):
                raise ValueError("All explicitly registered services must remain private loopback ports")
        bindings = ports[key]
        if (
            not isinstance(bindings, list)
            or len(bindings) != 1
            or not isinstance(bindings[0], dict)
            or bindings[0].get("HostIp") != "127.0.0.1"
            or not isinstance(bindings[0].get("HostPort"), str)
            or not re.fullmatch(r"[1-9][0-9]{0,4}", bindings[0]["HostPort"])
            or not 1 <= int(bindings[0]["HostPort"]) <= 65535
        ):
            raise ValueError("One exact IPv4 loopback port required")
        stamp = self.clock()
        _time(stamp)
        guard()
        return ResolvedPublishedEndpoint(
            r.container_id, r.container_port, int(bindings[0]["HostPort"]), stamp
        )
