import base64
import json
from dataclasses import asdict
from unittest.mock import Mock

import pytest

from adapters.onprem.blue_green import RemoteVmBlueGreenRouter
from domain.database import DatabaseBinding


@pytest.fixture
def router():
    source = asdict(
        DatabaseBinding(
            "org", "app", "shared_workload", "123456789012", "onprem", "shared", "appdb", "allocation"
        )
    )
    target = {**source, "role": "dedicated_workload", "instance_id": "dedicated"}
    registration = {
        "schema_version": 1,
        "application_id": "app",
        "organization_id": "org",
        "source": source,
        "target": target,
    }
    containers = {}
    for index, colour in enumerate(["router", "blue", "green"], 1):
        spec = {
            "name": "sky-" + colour,
            "container_id": str(index) * 64,
            "image_id": "sha256:" + str(index) * 64,
            "port": 8443 if colour == "router" else 8080,
        }
        registration[colour] = spec
        containers[spec["name"]] = {
            "Id": spec["container_id"],
            "Image": spec["image_id"],
            "State": {"Running": True},
            "Config": {
                "Labels": {
                    "sky-managed": "true",
                    "sky-application": "app",
                    "sky-organization": "org",
                    "sky-colour": colour,
                }
            },
            "HostConfig": {},
            "Mounts": [],
            "NetworkSettings": {"Networks": {"owned": {}}},
        }
    route = {"text": None}

    def command(args, **kw):
        if args[1] == "inspect":
            return json.dumps([containers[args[-1]]])
        if args[3] == "cat":
            return route["text"]
        if args[3] == "sh":
            route["text"] = base64.b64decode(args[-1]).decode()
            return ""
        raise AssertionError(args)

    instance = RemoteVmBlueGreenRouter(
        Mock(side_effect=command),
        registration,
        guard=Mock(),
        probe=lambda: {
            "binding": target if "sky-green:" in route["text"] else source,
            "revision": registration["green" if "sky-green:" in route["text"] else "blue"]["image_id"],
            "database_read_verified": True,
        },
    )
    route["text"] = instance.route_configuration(source)
    return instance, containers, route, source, target


def test_switch_and_reverse_require_exact_containers_and_live_db_probe(router, monkeypatch):
    monkeypatch.setattr("adapters.onprem.blue_green.time.sleep", lambda _: None)
    instance, _, _, source, target = router
    assert instance.current() == source
    assert instance.switch(source, target)["stable_entrypoint_verified"]
    assert instance.current() == target
    instance.switch(target, source)
    assert instance.current() == source


@pytest.mark.parametrize(
    "change", ["retired", "image", "container", "other_org", "socket", "root", "host_network"]
)
def test_unsafe_runtime_is_rejected_before_route_mutation(router, change):
    instance, containers, route, source, target = router
    before = route["text"]
    item = containers["sky-green"]
    if change == "retired":
        item["State"]["Running"] = False
    elif change == "image":
        item["Image"] = "sha256:" + "9" * 64
    elif change == "container":
        item["Id"] = "9" * 64
    elif change == "other_org":
        item["Config"]["Labels"]["sky-organization"] = "other"
    elif change == "socket":
        item["Mounts"] = [{"Destination": "/var/run/docker.sock", "Source": "/socket"}]
    elif change == "root":
        item["Mounts"] = [{"Destination": "/host", "Source": "/"}]
    else:
        item["HostConfig"]["NetworkMode"] = "host"
    with pytest.raises(ValueError):
        instance.switch(source, target)
    assert route["text"] == before


def test_unknown_reload_result_never_replays_mutation(router):
    instance, _, _, source, target = router
    original = instance.command.side_effect

    def failure(args, **kw):
        if args[1] == "exec" and args[3] == "sh":
            raise TimeoutError("connection lost after command submitted")
        return original(args, **kw)

    instance.command.side_effect = failure
    with pytest.raises(TimeoutError):
        instance.switch(source, target)
    calls = len(instance.command.call_args_list)
    with pytest.raises(RuntimeError):
        instance.switch(source, target)
    assert len(instance.command.call_args_list) == calls
