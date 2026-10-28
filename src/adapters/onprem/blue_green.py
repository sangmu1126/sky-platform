"""Owned Nginx entrypoint on the registered Docker-over-SSH host.

Requires two separately running applications and an exclusive durable operation.
Docker access is host administration, not a sandbox. Reloading Nginx does not
move existing WebSocket connections; writer/session drain is an app contract.
"""

import base64
import hashlib
import json
import re
import time
from copy import deepcopy

from domain.database import DatabaseBinding


class RemoteVmBlueGreenRouter:
    PATH = "/etc/nginx/sky/route.conf"

    def __init__(self, command, registration, *, guard, probe):
        if (
            not isinstance(registration, dict)
            or set(registration)
            != {
                "schema_version",
                "application_id",
                "organization_id",
                "router",
                "blue",
                "green",
                "source",
                "target",
            }
            or type(registration["schema_version"]) is not int
            or registration["schema_version"] != 1
        ):
            raise ValueError("Exact operator VM routing registration required")
        self.r = deepcopy(registration)
        self.bindings = [DatabaseBinding(**registration[key]) for key in ("source", "target")]
        left, right = self.bindings
        if (
            left.role != "shared_workload"
            or right.role != "dedicated_workload"
            or left.instance_id == right.instance_id
            or (left.application_id, left.organization_id, left.account_id, left.region)
            != (right.application_id, right.organization_id, right.account_id, right.region)
            or (left.application_id, left.organization_id)
            != (self.r["application_id"], self.r["organization_id"])
        ):
            raise ValueError("Same application source and target required")
        for colour in ("router", "blue", "green"):
            spec = self.r[colour]
            if (
                not isinstance(spec, dict)
                or set(spec) != {"name", "container_id", "image_id", "port"}
                or not re.fullmatch(r"[a-z][a-z0-9_-]{2,62}", spec["name"])
                or not re.fullmatch(r"[a-f0-9]{64}", spec["container_id"])
                or not re.fullmatch(r"sha256:[a-f0-9]{64}", spec["image_id"])
                or type(spec["port"]) is not int
                or not 1024 <= spec["port"] <= 65535
            ):
                raise ValueError("Immutable owned router/application containers required")
        if len({self.r[c]["container_id"] for c in ("router", "blue", "green")}) != 3:
            raise ValueError("Separate router, Blue and Green containers required")
        self.command, self.guard, self.probe_entrypoint = command, guard, probe
        self.uncertain = False

    def route_configuration(self, binding):
        if binding not in [self.r["source"], self.r["target"]]:
            raise ValueError("Unregistered VM routing binding")
        colour = "blue" if binding == self.r["source"] else "green"
        spec = self.r[colour]
        identity = hashlib.sha256(
            json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return f"# sky-route-v1 {identity}\nupstream sky_active {{ server {spec['name']}:{spec['port']}; }}\n"

    def _audit(self):
        self.guard()
        shared = None
        for colour in ("router", "blue", "green"):
            spec = self.r[colour]
            values = json.loads(
                self.command(["docker", "inspect", "--type", "container", spec["name"]], quiet=True)
            )
            if not isinstance(values, list) or len(values) != 1:
                raise ValueError("VM container inventory unavailable")
            container = values[0]
            labels = container.get("Config", {}).get("Labels", {})
            expected = {
                "sky-managed": "true",
                "sky-application": self.r["application_id"],
                "sky-organization": self.r["organization_id"],
                "sky-colour": colour,
            }
            if (
                container.get("Id") != spec["container_id"]
                or container.get("Image") != spec["image_id"]
                or container.get("State", {}).get("Running") is not True
                or container.get("HostConfig", {}).get("Privileged")
                or container.get("HostConfig", {}).get("NetworkMode") == "host"
                or any(labels.get(k) != v for k, v in expected.items())
            ):
                raise ValueError("VM container identity or ownership changed")
            for mount in container.get("Mounts", []):
                if (
                    mount.get("Destination") in {"/var/run/docker.sock", "/run/docker.sock"}
                    or mount.get("Source") == "/"
                ):
                    raise ValueError("VM application/router must not mount the Docker socket or host root")
            networks = set(container.get("NetworkSettings", {}).get("Networks", {}))
            shared = networks if shared is None else shared & networks
        if not shared or len(shared) != 1 or shared & {"host", "bridge", "none"}:
            raise ValueError("One shared dedicated Docker network required")
        self.guard()

    def current(self):
        if self.uncertain:
            raise RuntimeError("VM route outcome requires durable reconciliation")
        self._audit()
        text = self.command(["docker", "exec", self.r["router"]["name"], "cat", self.PATH], quiet=True)
        for binding in (self.r["source"], self.r["target"]):
            if text.rstrip("\n") == self.route_configuration(binding).rstrip("\n"):
                return deepcopy(binding)
        raise ValueError("VM route is not one of the registered configurations")

    def switch(self, expected_binding, target_binding):
        if expected_binding == target_binding or self.current() != expected_binding:
            raise ValueError("Current VM route differs from the approved transition")
        encoded = base64.b64encode(self.route_configuration(target_binding).encode()).decode()
        self.guard()
        self.uncertain = True
        # Configuration is generated from checked names and ports. All remote
        # commands are fixed; app source never supplies a shell command.
        script = "printf '%s' \"$1\" | base64 -d > /etc/nginx/sky/route.next\nmv /etc/nginx/sky/route.next /etc/nginx/sky/route.conf\nnginx -t\nnginx -s reload"
        self.command(
            ["docker", "exec", self.r["router"]["name"], "sh", "-ceu", script, "sky-route", encoded],
            quiet=True,
        )
        self.guard()
        # Check actual responses after reload, not just a changed config file.
        consecutive = 0
        for _ in range(30):
            try:
                self._verify_probe(target_binding)
            except (OSError, ValueError):
                consecutive = 0
            else:
                consecutive += 1
                if consecutive == 3:
                    break
            time.sleep(0.2)
        else:
            raise ValueError("VM router reload did not settle on the verified target")
        self.uncertain = False
        if self.current() != target_binding:
            self.uncertain = True
            raise ValueError("VM route changed after verification")
        return {
            "strategy": "blue_green",
            "binding": deepcopy(target_binding),
            "stable_entrypoint_verified": True,
            "websocket_sessions_preserved": False,
        }

    def _verify_probe(self, binding):
        colour = "blue" if binding == self.r["source"] else "green" if binding == self.r["target"] else None
        if colour is None:
            raise ValueError("Unregistered VM probe binding")
        self.guard()
        value = self.probe_entrypoint()
        if (
            not isinstance(value, dict)
            or value.get("binding") != binding
            or value.get("revision") != self.r[colour]["image_id"]
            or value.get("database_read_verified") is not True
        ):
            raise ValueError("Stable VM endpoint did not verify the expected app and database")
        self.guard()
        return {"binding": deepcopy(binding), "revision": value["revision"], "database_read_verified": True}

    def probe(self, expected_binding):
        if self.current() != expected_binding:
            raise ValueError("VM route differs before application probe")
        return self._verify_probe(expected_binding)
