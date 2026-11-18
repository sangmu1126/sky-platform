"""Pinned Nginx entrypoint for explicitly registered cross-environment apps.

Only new short HTTP requests move. No WebSocket/stream/session migration is
claimed. Caller must close all writers, hold execution ownership and persist
intents before switching. Unknown reload outcomes prohibit replay.
"""

import base64
import hashlib
import ipaddress
import json
import re
import time
from dataclasses import asdict, dataclass

from adapters.build.process import bounded_command
from adapters.onprem.database_inventory import PinnedVmInventoryCommand
from domain.database_transfer import RegisteredDatabaseTransfer

PATH = "/etc/nginx/sky/active.conf"
SWITCH_SCRIPT = (
    "printf '%s' \"$1\" | base64 -d > /etc/nginx/sky/active.next\n"
    "mv /etc/nginx/sky/active.next /etc/nginx/sky/active.conf\n"
    "nginx -t -c /etc/nginx/sky/nginx.conf\nnginx -s reload -c /etc/nginx/sky/nginx.conf"
)


@dataclass(frozen=True)
class RegisteredEnvironmentRouter:
    transfer: RegisteredDatabaseTransfer
    daemon_id: str
    container_id: str
    image_id: str
    source_address: str
    source_port: int
    source_tls_name: str
    target_address: str
    target_port: int
    target_tls_name: str
    network_name: str
    config_volume: str
    profile: str = "scores_v1"

    def __post_init__(self):
        if (
            not isinstance(self.transfer, RegisteredDatabaseTransfer)
            or not re.fullmatch(r"[a-zA-Z0-9-]{16,128}", self.daemon_id)
            or not re.fullmatch(r"[a-f0-9]{64}", self.container_id)
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", self.image_id)
            or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}", self.network_name)
            or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}", self.config_volume)
            or self.profile not in {"scores_v1", "tug_round_drain_v1"}
        ):
            raise ValueError("Immutable owned router registration required")
        for address, name, port in (
            (self.source_address, self.source_tls_name, self.source_port),
            (self.target_address, self.target_tls_name, self.target_port),
        ):
            if (
                not isinstance(address, str)
                or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}", address)
                or not isinstance(name, str)
                or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}", name)
                or type(port) is not int
                or not 1024 <= port <= 65535
            ):
                raise ValueError("Pinned upstream address, TLS identity and port required")
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                ip = None
            if ip is not None and (ip.is_unspecified or ip.is_multicast):
                raise ValueError("Unicast upstream required")

    def configuration(self, binding):
        if binding == asdict(self.transfer.source):
            address, port, name = self.source_address, self.source_port, self.source_tls_name
        elif binding == asdict(self.transfer.target):
            address, port, name = self.target_address, self.target_port, self.target_tls_name
        else:
            raise ValueError("Unregistered environment routing binding")
        identity = hashlib.sha256(
            json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if self.profile == "tug_round_drain_v1":
            common = (
                f"  proxy_pass https://{address}:{port};\n"
                f"  proxy_ssl_server_name on;\n  proxy_ssl_name {name};\n"
                "  proxy_ssl_trusted_certificate /etc/nginx/sky/ca.pem;\n"
                "  proxy_ssl_verify on;\n  proxy_ssl_verify_depth 2;\n"
                "  proxy_connect_timeout 3s;\n  proxy_send_timeout 5s;\n"
                "  proxy_next_upstream off;\n  proxy_http_version 1.1;\n"
                "  proxy_set_header Host $http_host;\n"
            )
            return (
                f"# sky-tug-environment-route-v1 {identity}\nserver {{\n"
                " listen 8443 ssl;\n listen 8080;\n"
                " ssl_certificate /etc/nginx/sky/gateway.pem;\n"
                " ssl_certificate_key /etc/nginx/sky/gateway.key;\n"
                " ssl_protocols TLSv1.2 TLSv1.3;\n client_max_body_size 16k;\n"
                " location = /control { return 404; }\n"
                " location = /ws {\n  limit_except GET { deny all; }\n"
                + common
                + "  proxy_set_header Upgrade $http_upgrade;\n"
                "  proxy_set_header Connection upgrade;\n  proxy_read_timeout 75s;\n }\n"
                " location / {\n  limit_except GET { deny all; }\n"
                + common
                + "  proxy_set_header Connection close;\n  proxy_read_timeout 30s;\n }\n}\n"
            )
        return (
            f"# sky-environment-route-v1 {identity}\nserver {{\n"
            " listen 8443 ssl;\n ssl_certificate /etc/nginx/sky/gateway.pem;\n"
            " ssl_certificate_key /etc/nginx/sky/gateway.key;\n ssl_protocols TLSv1.2 TLSv1.3;\n"
            " client_max_body_size 16k;\n location = /scores {\n"
            "  limit_except GET POST { deny all; }\n"
            f"  proxy_pass https://{address}:{port};\n  proxy_ssl_server_name on;\n  proxy_ssl_name {name};\n"
            "  proxy_ssl_trusted_certificate /etc/nginx/sky/ca.pem;\n  proxy_ssl_verify on;\n"
            "  proxy_ssl_verify_depth 2;\n  proxy_connect_timeout 3s;\n  proxy_read_timeout 5s;\n"
            "  proxy_send_timeout 5s;\n  proxy_next_upstream off;\n  proxy_http_version 1.1;\n"
            "  proxy_set_header Connection close;\n }\n location / { return 404; }\n}\n"
        )


class PinnedEnvironmentRouterCommand:
    """Reuse pinned SSH identity; permit only fixed router administration calls."""

    def __init__(self, ssh, registration):
        if not isinstance(ssh, PinnedVmInventoryCommand) or not isinstance(
            registration, RegisteredEnvironmentRouter
        ):
            raise TypeError("Pinned SSH and immutable router container required")
        self.ssh, self.container_id = ssh, registration.container_id
        self.payloads = frozenset(
            base64.b64encode(registration.configuration(asdict(p)).encode()).decode()
            for p in (registration.transfer.source, registration.transfer.target)
        )

    def __call__(self, arguments):
        import shlex

        allowed = (
            arguments == ["info", "--format", "{{json .ID}}"]
            or arguments == ["inspect", self.container_id]
            or arguments == ["exec", self.container_id, "cat", PATH]
            or (
                len(arguments) == 7
                and arguments[:6]
                == ["exec", self.container_id, "sh", "-ceu", SWITCH_SCRIPT, "sky-environment-route"]
                and isinstance(arguments[6], str)
                and arguments[6] in self.payloads
            )
        )
        if not allowed:
            raise ValueError("Only fixed registered router commands permitted")
        code, output = bounded_command(
            [*self.ssh.arguments, shlex.join(["sudo", "-n", "docker", *arguments])],
            timeout=20,
            output_limit=65536,
        )
        if code:
            raise RuntimeError("Registered router command outcome requires reconciliation")
        return output


class EnvironmentNginxRouter:
    def __init__(self, registration, command, *, guard, verify_runtime, probe_entrypoint, sleep=time.sleep):
        if not isinstance(registration, RegisteredEnvironmentRouter):
            raise TypeError("Typed environment router registration required")
        self.registration, self.command, self.guard = registration, command, guard
        self.verify_runtime, self.probe_entrypoint, self.sleep = verify_runtime, probe_entrypoint, sleep
        self.bindings = [asdict(registration.transfer.source), asdict(registration.transfer.target)]
        self.uncertain = False

    def _audit(self):
        self.guard()
        r = self.registration
        if json.loads(self.command(["info", "--format", "{{json .ID}}"])) != r.daemon_id:
            raise ValueError("Router Docker daemon changed")
        (container,) = json.loads(self.command(["inspect", r.container_id]))
        labels = container.get("Config", {}).get("Labels", {})
        required = {
            "sky-managed": "true",
            "sky-organization-id": r.transfer.source.organization_id,
            "sky-application-id": r.transfer.source.application_id,
            "sky-owner-ref": r.transfer.source.owner_ref,
            "sky-role": "environment-router",
        }
        if (
            container.get("Id") != r.container_id
            or container.get("Image") != r.image_id
            or container.get("State", {}).get("Running") is not True
            or container.get("HostConfig", {}).get("Privileged") is not False
            or container.get("HostConfig", {}).get("ReadonlyRootfs") is not True
            or container.get("HostConfig", {}).get("NetworkMode") in {"host", "none"}
            or set(container.get("NetworkSettings", {}).get("Networks", {})) != {r.network_name}
            or any(labels.get(k) != v for k, v in required.items())
            or any(
                m.get("Source") == "/" or m.get("Destination") in {"/run/docker.sock", "/var/run/docker.sock"}
                for m in container.get("Mounts", [])
            )
        ):
            raise ValueError("Router ownership or execution changed")
        mounts = container.get("Mounts", [])
        volumes = [m for m in mounts if m.get("Type") == "volume"]
        if (
            len(volumes) != 1
            or volumes[0].get("Name") != r.config_volume
            or volumes[0].get("Destination") != "/etc/nginx/sky"
            or volumes[0].get("RW") is not True
            or any(m.get("Type") not in {"volume", "tmpfs"} for m in mounts)
        ):
            raise ValueError("Router configuration volume changed")
        for binding in self.bindings:
            if self.verify_runtime(binding) is not True:
                raise ValueError("Registered application runtime verification required")
        self.guard()

    def current(self):
        if self.uncertain:
            raise RuntimeError("Router outcome requires reconciliation")
        self._audit()
        value = self.command(["exec", self.registration.container_id, "cat", PATH])
        for binding in self.bindings:
            if value == self.registration.configuration(binding):
                return dict(binding)
        raise ValueError("Router configuration differs from registration")

    def _probe(self, binding):
        if binding not in self.bindings:
            raise ValueError("Unregistered routing probe")
        self.guard()
        result = self.probe_entrypoint()
        identity = hashlib.sha256(
            json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if not isinstance(result, dict) or result.get("binding_hash") != identity:
            raise ValueError("Actual HTTPS entrypoint read differs from expected runtime")
        self.guard()
        return {"binding": binding, "verified_scope": "routed_https_database_read"}

    def probe(self, binding):
        if self.current() != binding:
            raise ValueError("Unexpected active route")
        return self._probe(binding)

    def switch(self, expected_binding, target_binding):
        if (
            expected_binding == target_binding
            or target_binding not in self.bindings
            or self.current() != expected_binding
        ):
            raise ValueError("Registered current route required before switching")
        encoded = base64.b64encode(self.registration.configuration(target_binding).encode()).decode()
        self.guard()
        self.uncertain = True
        self.command(
            [
                "exec",
                self.registration.container_id,
                "sh",
                "-ceu",
                SWITCH_SCRIPT,
                "sky-environment-route",
                encoded,
            ]
        )
        successes = 0
        for _ in range(30):
            self.guard()
            try:
                self._probe(target_binding)
            except (OSError, ValueError):
                successes = 0
            else:
                successes += 1
                if successes == 3:
                    break
            self.sleep(0.2)
        else:
            raise RuntimeError("Router reload not verified; reconcile before replay")
        self.guard()
        self.uncertain = False
        try:
            if self.current() != target_binding:
                raise ValueError("Route changed after verification")
        except Exception:
            self.uncertain = True
            raise
        return {
            "strategy": "blue_green",
            "binding": target_binding,
            "stable_entrypoint_verified": True,
            "websocket_sessions_preserved": False,
            "write_pause_required": True,
        }
