import base64
import hashlib
import json
from dataclasses import asdict, replace
from unittest.mock import Mock, patch

import pytest

from adapters.onprem.database_inventory import PinnedVmInventoryCommand
from adapters.onprem.environment_router import (
    PATH,
    SWITCH_SCRIPT,
    EnvironmentNginxRouter,
    PinnedEnvironmentRouterCommand,
    RegisteredEnvironmentRouter,
)
from tests.unit.test_database_transfer import transfer


def registration():
    return RegisteredEnvironmentRouter(
        transfer(),
        "daemon-1234567890",
        "a" * 64,
        "sha256:" + "b" * 64,
        "192.0.2.1",
        8443,
        "source.test",
        "target.internal",
        8443,
        "target.test",
        "owned-network",
        "owned-config",
    )


def fixture():
    r = registration()
    source, target = asdict(r.transfer.source), asdict(r.transfer.target)
    state = {"configuration": r.configuration(source), "binding": source}
    container = {
        "Id": r.container_id,
        "Image": r.image_id,
        "State": {"Running": True},
        "HostConfig": {"Privileged": False, "ReadonlyRootfs": True, "NetworkMode": "owned-network"},
        "Config": {
            "Labels": {
                "sky-managed": "true",
                "sky-organization-id": "org",
                "sky-application-id": "app",
                "sky-owner-ref": "source-owner",
                "sky-role": "environment-router",
            }
        },
        "Mounts": [{"Type": "volume", "Name": "owned-config", "Destination": "/etc/nginx/sky", "RW": True}],
        "NetworkSettings": {"Networks": {"owned-network": {}}},
    }

    def command(args):
        if args == ["info", "--format", "{{json .ID}}"]:
            return json.dumps(r.daemon_id)
        if args == ["inspect", r.container_id]:
            return json.dumps([container])
        if args == ["exec", r.container_id, "cat", PATH]:
            return state["configuration"]
        assert args[:6] == ["exec", r.container_id, "sh", "-ceu", SWITCH_SCRIPT, "sky-environment-route"]
        state["configuration"] = base64.b64decode(args[6]).decode()
        state["binding"] = target
        return ""

    def probe():
        return {
            "binding_hash": hashlib.sha256(
                json.dumps(state["binding"], sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        }

    runtime = Mock(return_value=True)
    router = EnvironmentNginxRouter(
        r,
        Mock(side_effect=command),
        guard=lambda: None,
        verify_runtime=runtime,
        probe_entrypoint=probe,
        sleep=lambda _: None,
    )
    return router, state, container


def test_switch_requires_real_matching_entrypoint_reads_after_reload():
    router, _, _ = fixture()
    source, target = router.bindings
    assert router.current() == source
    result = router.switch(source, target)
    assert result["stable_entrypoint_verified"] and result["write_pause_required"]
    assert result["websocket_sessions_preserved"] is False
    assert router.current() == target


def test_failed_read_or_lost_reload_outcome_cannot_replay_switch():
    router, _, _ = fixture()
    source, target = router.bindings
    router.probe_entrypoint = lambda: {"binding_hash": "wrong"}
    with pytest.raises(RuntimeError, match="reconcile"):
        router.switch(source, target)
    assert router.uncertain
    calls = router.command.call_count
    with pytest.raises(RuntimeError, match="reconciliation"):
        router.current()
    assert router.command.call_count == calls


@pytest.mark.parametrize(
    "change",
    [
        {"Id": "c" * 64},
        {"Image": "sha256:" + "c" * 64},
        {"State": {"Running": False}},
        {"HostConfig": {"Privileged": True, "NetworkMode": "owned-network"}},
        {"Config": {"Labels": {}}},
        {"Mounts": [{"Source": "/", "Destination": "/host"}]},
    ],
)
def test_foreign_unsafe_or_stopped_router_prevents_any_switch(change):
    router, _, container = fixture()
    container.update(change)
    with pytest.raises(ValueError, match="ownership"):
        router.current()
    assert not any(
        call.args[0][:3] == ["exec", router.registration.container_id, "sh"]
        for call in router.command.call_args_list
    )


def test_runtime_verification_is_required_in_addition_to_router_config():
    router, _, _ = fixture()
    router.verify_runtime.return_value = False
    with pytest.raises(ValueError, match="runtime"):
        router.current()


@pytest.mark.parametrize(
    "address", ["127.0.0.1; command", "host\nreturn 200;", "$(id)", "0.0.0.0", "224.0.0.1"]
)
def test_upstream_configuration_cannot_inject_nginx_or_shell(address):
    with pytest.raises(ValueError):
        replace(registration(), source_address=address)


def test_pinned_command_only_accepts_the_two_registered_configurations():
    r = registration()
    ssh = Mock(spec=PinnedVmInventoryCommand)
    ssh.arguments = ["ssh", "pinned"]
    command = PinnedEnvironmentRouterCommand(ssh, r)
    prefix = ["exec", r.container_id, "sh", "-ceu", SWITCH_SCRIPT, "sky-environment-route"]
    with patch("adapters.onprem.environment_router.bounded_command", return_value=(0, "")) as run:
        command([*prefix, base64.b64encode(r.configuration(asdict(r.transfer.target)).encode()).decode()])
        assert run.call_count == 1
        with pytest.raises(ValueError):
            command([*prefix, base64.b64encode(b"arbitrary config").decode()])
        with pytest.raises(ValueError):
            command(["exec", r.container_id, "sh", "-c", "arbitrary command"])
        assert run.call_count == 1
