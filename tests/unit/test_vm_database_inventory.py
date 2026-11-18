"""Remote resource observations require pinned identities, persistence and ownership."""

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime
from unittest.mock import Mock, patch

import pytest

from adapters.onprem.database_inventory import (
    PinnedVmInventoryCommand,
    VmDatabaseInventoryRegistration,
    VmDatabaseInventoryVerifier,
)
from domain.database_inventory import DatabaseInventoryUnavailable
from domain.database_migration import DatabaseLocation, DatabasePlacement

KNOWN_HOST = (
    "[127.0.0.1]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g\n"
)


@pytest.fixture
def registered():
    placement = DatabasePlacement(
        "org",
        "app",
        "existing_workload",
        DatabaseLocation("onprem", "vm_postgresql", "vm-one", "dc-a"),
        "pg-one",
        "app_db",
        "owner",
        17,
    )
    r = VmDatabaseInventoryRegistration(
        placement, "daemon-12345678", "a" * 64, "sha256:" + "b" * 64, "owned-volume", "127.0.0.1", 5432
    )
    labels = {
        "sky-managed": "true",
        "sky-organization-id": "org",
        "sky-application-id": "app",
        "sky-owner-ref": "owner",
        "sky-database-role": "existing_workload",
    }
    container = {
        "id": r.container_id,
        "image": r.image_id,
        "running": True,
        "privileged": False,
        "network_mode": "bridge",
        "labels": dict(labels),
        "mounts": [
            {"Type": "volume", "Name": r.volume_name, "RW": True, "Destination": "/var/lib/postgresql/data"}
        ],
        "ports": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "5432"}]},
    }
    volume = {
        "name": r.volume_name,
        "driver": "local",
        "scope": "local",
        "options": False,
        "labels": dict(labels),
    }
    command = Mock(
        side_effect=lambda args: json.dumps(
            r.daemon_id if args[0] == "info" else container if args[0] == "inspect" else volume
        )
    )
    return VmDatabaseInventoryVerifier(r, command, clock=lambda: datetime.now(UTC)), container, volume


def test_valid_vm_reads_only_fixed_metadata_and_returns_no_environment(registered):
    verifier, _, _ = registered
    proof = verifier.verify(verifier.registration.placement)
    assert proof.placement == verifier.registration.placement
    assert proof.evidence_ref.startswith("VM-")
    assert len(verifier.command.call_args_list) == 3
    assert not any("Env" in str(call) for call in verifier.command.call_args_list)


@pytest.mark.parametrize(
    "change",
    [
        lambda c, v: c.update(id="f" * 64),
        lambda c, v: c.update(image="sha256:" + "f" * 64),
        lambda c, v: c["labels"].update({"sky-application-id": "foreign"}),
        lambda c, v: c.update(privileged=True),
        lambda c, v: c.update(network_mode="host"),
        lambda c, v: c["mounts"][0].update(Type="tmpfs"),
        lambda c, v: c["mounts"].append({"Source": "/", "Destination": "/host"}),
        lambda c, v: c["ports"]["5432/tcp"][0].update(HostIp="0.0.0.0"),
        lambda c, v: v["labels"].update({"sky-owner-ref": "foreign"}),
        lambda c, v: v.update(options=True),
    ],
)
def test_vm_drift_or_unsafe_persistence_blocks_proof(registered, change):
    verifier, container, volume = registered
    change(container, volume)
    with pytest.raises(DatabaseInventoryUnavailable):
        verifier.verify(verifier.registration.placement)


def test_foreign_placement_does_not_trigger_remote_commands(registered):
    verifier, _, _ = registered
    with pytest.raises(ValueError):
        verifier.verify(replace(verifier.registration.placement, application_id="foreign"))
    verifier.command.assert_not_called()


def test_duplicate_remote_metadata_fields_cannot_prove_inventory(registered):
    verifier, _, _ = registered
    verifier.command = Mock(
        side_effect=[json.dumps(verifier.registration.daemon_id), '{"id":"one","id":"two"}']
    )
    with pytest.raises(DatabaseInventoryUnavailable):
        verifier.verify(verifier.registration.placement)


def test_transport_requires_private_pinned_host_key_and_rejects_mutations(tmp_path):
    key, hosts = tmp_path / "key", tmp_path / "known_hosts"
    key.write_text("unit-test-placeholder")
    hosts.write_text(KNOWN_HOST)
    key.chmod(0o600)
    hosts.chmod(0o600)
    command = PinnedVmInventoryCommand(
        host="127.0.0.1",
        user="operator",
        port=2222,
        private_key=key,
        known_hosts=hosts,
        private_key_sha256=hashlib.sha256(key.read_bytes()).hexdigest(),
        known_hosts_sha256=hashlib.sha256(hosts.read_bytes()).hexdigest(),
    )
    with patch("adapters.onprem.database_inventory.bounded_command", return_value=(0, '"daemon"')) as run:
        assert command(["info", "--format", "{{json .ID}}"]) == '"daemon"'
        arguments = run.call_args.args[0]
        assert "StrictHostKeyChecking=yes" in arguments and "ForwardAgent=no" in arguments
        assert "IdentityAgent=none" in arguments and "PreferredAuthentications=publickey" in arguments
        assert "IdentityFile=none" in arguments and "CertificateFile=none" in arguments
        assert "PubkeyAuthentication=yes" in arguments and "HostbasedAuthentication=no" in arguments
        assert "GSSAPIAuthentication=no" in arguments and "AddKeysToAgent=no" in arguments
        assert "PasswordAuthentication=no" in arguments and "KbdInteractiveAuthentication=no" in arguments
        assert "ProxyCommand=none" in arguments and "ControlMaster=no" in arguments
        assert "ProxyJump=none" in arguments and "CanonicalizeHostname=no" in arguments
        assert "Hostname=127.0.0.1" in arguments and "RequestTTY=no" in arguments
        assert "ConnectionAttempts=1" in arguments and "NumberOfPasswordPrompts=0" in arguments
        assert "ForwardX11=no" in arguments and "ForwardX11Trusted=no" in arguments
        assert "Tunnel=no" in arguments and "EscapeChar=none" in arguments
        assert arguments[arguments.index("-F") + 2] == "-T"
        assert "ControlPath=none" in arguments and "UpdateHostKeys=no" in arguments
        assert "HostKeyAlgorithms=ssh-ed25519" in arguments
        assert arguments[0] == "/usr/bin/ssh"
        assert arguments[-1].startswith(
            "/usr/bin/sudo -n /usr/bin/docker --host unix:///var/run/docker.sock info"
        )
        assert run.call_args.kwargs["output_limit"] == 65536
        assert dict(run.call_args.kwargs["env"]) == {
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        }
        with pytest.raises(ValueError):
            command(["exec", "container", "sh"])
        assert run.call_count == 1
        key.write_text("changed-after-construction")
        with pytest.raises(ValueError, match="operator-private"):
            command(["info", "--format", "{{json .ID}}"])
        assert run.call_count == 1
    hosts.chmod(0o644)
    with pytest.raises(ValueError):
        PinnedVmInventoryCommand(
            host="127.0.0.1",
            user="operator",
            port=2222,
            private_key=key,
            known_hosts=hosts,
            private_key_sha256=hashlib.sha256(key.read_bytes()).hexdigest(),
            known_hosts_sha256=hashlib.sha256(hosts.read_bytes()).hexdigest(),
        )


@pytest.mark.parametrize("host", ["8.8.8.8", "169.254.169.254", "vm.example", "127.0.0.01"])
def test_transport_rejects_public_metadata_dns_or_noncanonical_addresses(tmp_path, host):
    key, hosts = tmp_path / "key", tmp_path / "known_hosts"
    key.write_text("unit-test-placeholder")
    hosts.write_text(KNOWN_HOST)
    key.chmod(0o600)
    hosts.chmod(0o600)
    with pytest.raises(ValueError, match="private SSH address"):
        PinnedVmInventoryCommand(
            host=host,
            user="operator",
            port=2222,
            private_key=key,
            known_hosts=hosts,
            private_key_sha256=hashlib.sha256(key.read_bytes()).hexdigest(),
            known_hosts_sha256=hashlib.sha256(hosts.read_bytes()).hexdigest(),
        )


def test_transport_rejects_private_file_digest_drift(tmp_path):
    key, hosts = tmp_path / "key", tmp_path / "known_hosts"
    key.write_text("unit-test-placeholder")
    hosts.write_text(KNOWN_HOST)
    key.chmod(0o600)
    hosts.chmod(0o600)
    with pytest.raises(ValueError, match="operator-private"):
        PinnedVmInventoryCommand(
            host="127.0.0.1",
            user="operator",
            port=2222,
            private_key=key,
            known_hosts=hosts,
            private_key_sha256="0" * 64,
            known_hosts_sha256=hashlib.sha256(hosts.read_bytes()).hexdigest(),
        )


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1 ssh-ed25519 AAAA\n",
        "[127.0.0.1]:22 ssh-ed25519 AAAA\n",
        KNOWN_HOST.rstrip("\n"),
        KNOWN_HOST + KNOWN_HOST,
        KNOWN_HOST.replace("ssh-ed25519", "ssh-rsa"),
        "[127.0.0.1]:2222 ssh-ed25519 AAAA\n",
    ],
)
def test_transport_rejects_known_host_not_bound_to_exact_target(tmp_path, value):
    key, hosts = tmp_path / "key", tmp_path / "known_hosts"
    key.write_text("unit-test-placeholder")
    hosts.write_text(value)
    key.chmod(0o600)
    hosts.chmod(0o600)
    with pytest.raises(ValueError, match="Exact pinned Ed25519"):
        PinnedVmInventoryCommand(
            host="127.0.0.1",
            user="operator",
            port=2222,
            private_key=key,
            known_hosts=hosts,
            private_key_sha256=hashlib.sha256(key.read_bytes()).hexdigest(),
            known_hosts_sha256=hashlib.sha256(hosts.read_bytes()).hexdigest(),
        )
