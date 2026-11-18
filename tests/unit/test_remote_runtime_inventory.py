"""Pinned SSH runtime observations are independently evaluated and sanitized."""

import hashlib
import json
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from unittest.mock import Mock, patch

import pytest

from adapters.onprem.runtime_inventory import (
    PinnedVmRuntimeObservationTransport,
    remote_runtime_authority_ref,
)
from adapters.runtime.workload_inventory import (
    RemoteLinuxWorkloadInventoryReader,
    collect_linux_proc_observation,
)
from interfaces.runtime_inventory_helper import registered_runtime_observation
from ports.workload_inventory import WorkloadInventoryUnavailable
from tests.unit.test_environment_transition import NOW
from tests.unit.test_runtime_workload_inventory import runtime_case


def identity_files(tmp_path):
    key = tmp_path / "id_ed25519"
    hosts = tmp_path / "known_hosts"
    key.write_text("PRIVATE TEST FIXTURE\n")
    hosts.write_text("vm.example ssh-ed25519 TEST-FIXTURE\n")
    key.chmod(0o600)
    hosts.chmod(0o600)
    return key, hosts


def remote_case(tmp_path, *, extra_file=False):
    template, source, proc, _published = runtime_case(tmp_path, extra_file=extra_file)
    key, hosts = identity_files(tmp_path)
    authority = remote_runtime_authority_ref("vm.example", "sky_inventory", 22, hosts)
    registration = replace(template.registration, authority_ref=authority)
    observation = collect_linux_proc_observation(registration.document(), proc, clock=lambda: NOW)
    published = {}

    class Transport:
        def observe(self, value):
            assert value == registration
            return deepcopy(observation)

    class Publisher:
        def publish(self, report):
            published[report["report_id"]] = report
            return report["report_id"]

    reader = RemoteLinuxWorkloadInventoryReader(
        registration,
        Transport(),
        Publisher(),
        clock=lambda: NOW,
    )
    return reader, source, proc, observation, published, key, hosts


def reidentify(observation):
    unsigned = {key: value for key, value in observation.items() if key != "observation_id"}
    observation["observation_id"] = (
        "WRO-"
        + hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
    )


def test_remote_observation_is_reassessed_before_runtime_evidence_is_published(tmp_path):
    reader, source, _proc, _observation, published, _key, _hosts = remote_case(tmp_path)
    snapshot = reader.collect(source.inventory, "source")
    report = published[snapshot.evidence_refs[0]]
    assert report["status"] == "verified"
    assert report["observed_probes"] == [["local-file", "jobs"], ["session", "api"]]
    assert snapshot.observed_at == NOW


def test_stale_or_tampered_remote_observation_never_publishes(tmp_path):
    reader, source, _proc, observation, published, _key, _hosts = remote_case(tmp_path)
    observation["observed_at"] = (NOW - timedelta(seconds=31)).isoformat()
    reidentify(observation)
    reader.transport.observe = Mock(return_value=observation)
    with pytest.raises(WorkloadInventoryUnavailable):
        reader.collect(source.inventory, "source")
    assert not published
    observation["processes"][0]["uid"] = 0
    reidentify(observation)
    with pytest.raises(WorkloadInventoryUnavailable):
        reader.collect(source.inventory, "source")
    assert not published


def test_remote_unknown_writer_is_durable_blocked_without_leaking_path(tmp_path):
    reader, source, _proc, _observation, published, _key, _hosts = remote_case(tmp_path, extra_file=True)
    with pytest.raises(WorkloadInventoryUnavailable):
        reader.collect(source.inventory, "source")
    report = next(iter(published.values()))
    assert report["status"] == "blocked"
    assert report["processes"][1]["unexpected_writer_count"] == 1
    assert "/private/leak.txt" not in json.dumps(report)


def test_pinned_transport_uses_only_fixed_helper_and_exact_registration(tmp_path):
    reader, _source, _proc, observation, _published, key, hosts = remote_case(tmp_path)
    guard = Mock()
    transport = PinnedVmRuntimeObservationTransport(
        host="vm.example",
        user="sky_inventory",
        port=22,
        private_key=key,
        known_hosts=hosts,
        guard=guard,
    )
    with patch(
        "adapters.onprem.runtime_inventory.bounded_command",
        return_value=(0, json.dumps(observation)),
    ) as command:
        assert transport.observe(reader.registration) == observation
    arguments = command.call_args.args[0]
    assert arguments[-1] == (
        "sudo -n /usr/local/bin/sky-runtime-inventory-helper --registration "
        + reader.registration.document()["runtime_registration_id"]
        + " --format json-v1"
    )
    assert "ClearAllForwardings=yes" in arguments
    assert guard.call_count == 2
    with pytest.raises(ValueError, match="authority"):
        transport.observe(replace(reader.registration, authority_ref="other-authority"))


def test_changed_ssh_identity_and_remote_diagnostics_are_sanitized(tmp_path):
    reader, _source, _proc, _observation, _published, key, hosts = remote_case(tmp_path)
    transport = PinnedVmRuntimeObservationTransport(
        host="vm.example",
        user="sky_inventory",
        port=22,
        private_key=key,
        known_hosts=hosts,
        guard=lambda: None,
    )
    key.write_text("CHANGED PRIVATE FIXTURE\n")
    with (
        patch("adapters.onprem.runtime_inventory.bounded_command") as command,
        pytest.raises(WorkloadInventoryUnavailable, match="Pinned VM runtime observation unavailable"),
    ):
        transport.observe(reader.registration)
    command.assert_not_called()


def test_duplicate_remote_observation_fields_are_sanitized(tmp_path):
    reader, _source, _proc, _observation, _published, key, hosts = remote_case(tmp_path)
    transport = PinnedVmRuntimeObservationTransport(
        host="vm.example",
        user="sky_inventory",
        port=22,
        private_key=key,
        known_hosts=hosts,
        guard=lambda: None,
    )
    with (
        patch(
            "adapters.onprem.runtime_inventory.bounded_command",
            return_value=(0, '{"runtime_registration_id":"one","runtime_registration_id":"two"}'),
        ),
        pytest.raises(WorkloadInventoryUnavailable, match="Pinned VM runtime observation unavailable"),
    ):
        transport.observe(reader.registration)


def test_root_registry_helper_reads_only_exact_immutable_registration(tmp_path):
    reader, _source, proc, _observation, _published, _key, _hosts = remote_case(tmp_path)
    registry = tmp_path / "registry"
    registry.mkdir()
    registration = reader.registration.document()
    path = registry / (registration["runtime_registration_id"] + ".json")
    path.write_text(json.dumps(registration))
    path.chmod(0o600)
    result = registered_runtime_observation(
        registration["runtime_registration_id"],
        registry_root=registry,
        proc_root=proc,
        clock=lambda: NOW,
        require_root_ownership=False,
    )
    assert result["runtime_registration_id"] == registration["runtime_registration_id"]
    path.chmod(0o666)
    with pytest.raises(ValueError, match="Root-owned immutable"):
        registered_runtime_observation(
            registration["runtime_registration_id"],
            registry_root=registry,
            proc_root=proc,
            clock=lambda: NOW,
            require_root_ownership=False,
        )
