import json
from copy import deepcopy
from datetime import UTC, datetime

import pytest

from adapters.onprem.published_endpoint import (
    PinnedPublishedEndpointRegistration,
    PinnedPublishedEndpointResolver,
)


def case():
    registration = PinnedPublishedEndpointRegistration(
        "trusted-daemon",
        "a" * 64,
        "sha256:" + "b" * 64,
        "org",
        "app",
        "owner",
        "run-1",
        "registered-network",
        5432,
    )
    metadata = {
        "id": registration.container_id,
        "image": registration.image_id,
        "running": True,
        "privileged": False,
        "network_mode": "registered-network",
        "labels": {
            "sky-managed": "true",
            "sky-organization-id": "org",
            "sky-application-id": "app",
            "sky-owner-ref": "owner",
            "sky.validation": "run-1",
        },
        "ports": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "31000"}]},
    }
    calls = []

    def command(arguments):
        calls.append(arguments)
        return json.dumps("trusted-daemon" if arguments[0] == "info" else metadata)

    return registration, metadata, command, calls


def test_new_port_is_resolved_without_adopting_another_container_or_disabling_tls():
    registration, metadata, command, calls = case()
    resolver = PinnedPublishedEndpointResolver(registration, command, clock=lambda: datetime.now(UTC))
    first = resolver.resolve(guard=lambda: None)
    metadata["ports"]["5432/tcp"][0]["HostPort"] = "32000"
    second = resolver.resolve(guard=lambda: None)
    assert first.host_port == 31000 and second.host_port == 32000
    assert first.container_id == second.container_id == registration.container_id
    assert first.host_address == second.host_address == "127.0.0.1"
    assert all(value[0] in {"info", "inspect"} for value in calls)


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", "c" * 64),
        ("image", "sha256:" + "c" * 64),
        ("running", False),
        ("privileged", True),
        ("network_mode", "host"),
        ("labels", {}),
    ],
)
def test_changed_resource_identity_or_ownership_is_never_a_new_endpoint(field, value):
    registration, metadata, command, _ = case()
    metadata[field] = value
    with pytest.raises(ValueError):
        PinnedPublishedEndpointResolver(registration, command).resolve(guard=lambda: None)


@pytest.mark.parametrize(
    "binding",
    [
        {"HostIp": "0.0.0.0", "HostPort": "31000"},
        {"HostIp": "127.0.0.2", "HostPort": "31000"},
        {"HostIp": "127.0.0.1", "HostPort": "65536"},
        {"HostIp": "127.0.0.1", "HostPort": "-oProxyCommand=bad"},
    ],
)
def test_public_or_unregistered_bindings_and_option_injection_are_rejected(binding):
    registration, metadata, command, _ = case()
    metadata["ports"]["5432/tcp"] = [binding]
    with pytest.raises(ValueError):
        PinnedPublishedEndpointResolver(registration, command).resolve(guard=lambda: None)


def test_ambiguous_extra_service_or_membership_revocation_prevents_result():
    registration, metadata, command, _ = case()
    metadata["ports"]["9999/tcp"] = deepcopy(metadata["ports"]["5432/tcp"])
    with pytest.raises(ValueError):
        PinnedPublishedEndpointResolver(registration, command).resolve(guard=lambda: None)
    del metadata["ports"]["9999/tcp"]

    def revoked():
        raise PermissionError("Current membership revoked")

    with pytest.raises(PermissionError):
        PinnedPublishedEndpointResolver(registration, command).resolve(guard=revoked)


def test_duplicate_remote_port_fields_are_rejected():
    registration, _metadata, _command, _ = case()
    command = lambda arguments: (
        json.dumps(registration.daemon_id)
        if arguments[0] == "info"
        else '{"id":"' + registration.container_id + '","ports":{},"ports":{}}'
    )
    with pytest.raises(ValueError, match="Duplicate"):
        PinnedPublishedEndpointResolver(registration, command).resolve(guard=lambda: None)


def test_game_control_and_play_ports_must_both_be_registered_and_loopback():
    from dataclasses import replace

    registration, metadata, command, _ = case()
    registration = replace(registration, additional_container_ports=(8444,))
    metadata["ports"]["8444/tcp"] = [{"HostIp": "127.0.0.1", "HostPort": "32000"}]
    result = PinnedPublishedEndpointResolver(registration, command).resolve(guard=lambda: None)
    assert result.host_address == "127.0.0.1"
    metadata["ports"]["8444/tcp"][0]["HostIp"] = "0.0.0.0"
    with pytest.raises(ValueError, match="private loopback"):
        PinnedPublishedEndpointResolver(registration, command).resolve(guard=lambda: None)
