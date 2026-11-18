"""Remote runtime helper installation is content-bound and least-privilege."""

import base64
import hashlib
import json
import os
import struct
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from unittest.mock import patch

import pytest

from adapters.onprem.runtime_inventory_install import (
    RUNTIME_GATE_PATH,
    RUNTIME_HELPER_PATH,
    RUNTIME_REGISTRY_PATH,
    RUNTIME_SUDOERS_PATH,
    RuntimeInventoryHostPolicy,
    install_runtime_registration,
    verify_runtime_host_install,
)
from interfaces.runtime_inventory_ssh_gate import SUDO_PATH, main, validated_sudo_command
from tests.unit.test_runtime_workload_inventory import runtime_case


def public_key():
    kind = b"ssh-ed25519"
    key = bytes(range(32))
    raw = struct.pack(">I", len(kind)) + kind + struct.pack(">I", len(key)) + key
    return "ssh-ed25519 " + base64.b64encode(raw).decode() + " fixture-comment"


def policy(tmp_path):
    helper = b"#!/bin/sh\nexec helper\n"
    gate = b"#!/bin/sh\nexec gate\n"
    value = RuntimeInventoryHostPolicy(
        "ssh-" + "1" * 64,
        "sky_inventory",
        os.getuid(),
        public_key(),
        hashlib.sha256(helper).hexdigest(),
        hashlib.sha256(gate).hexdigest(),
    )
    return value, helper, gate


def write(root, absolute_path, data, mode):
    path = root / absolute_path.removeprefix("/")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)
    return path


def test_host_policy_forces_one_key_command_and_digest_pinned_sudo(tmp_path):
    value, _helper, _gate = policy(tmp_path)
    authorized = value.authorized_keys()
    sudoers = value.sudoers()
    assert authorized.startswith('restrict,command="/usr/local/bin/sky-runtime-inventory-ssh-gate",')
    assert "no-agent-forwarding,no-port-forwarding,no-pty,no-user-rc,no-X11-forwarding" in authorized
    assert authorized.endswith(" sky-runtime-inventory\n")
    assert "NOPASSWD: sha256:" + value.helper_sha256 in sudoers
    assert RUNTIME_HELPER_PATH + " *" in sudoers
    assert value.public_key not in json.dumps(value.document())


def test_forced_command_gate_rejects_shell_and_executes_only_exact_helper():
    registration_id = "WRR-" + "a" * 64
    original = "sudo -n " + RUNTIME_HELPER_PATH + " --registration " + registration_id + " --format json-v1"
    assert validated_sudo_command(original) == [
        SUDO_PATH,
        "-n",
        RUNTIME_HELPER_PATH,
        "--registration",
        registration_id,
        "--format",
        "json-v1",
    ]
    for changed in (
        original + "; id",
        original.replace("json-v1", "json-v1 --extra"),
        original.replace(registration_id, "../../etc/shadow"),
        "sudo -n /bin/sh",
    ):
        with pytest.raises(ValueError, match="fixed runtime inventory helper"):
            validated_sudo_command(changed)
    with (
        patch.dict("os.environ", {"SSH_ORIGINAL_COMMAND": original}, clear=True),
        patch("interfaces.runtime_inventory_ssh_gate.os.execve") as execute,
    ):
        main()
    assert execute.call_args.args[0] == SUDO_PATH
    assert execute.call_args.args[1][2] == RUNTIME_HELPER_PATH
    assert execute.call_args.args[2] == {
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    }


def test_registration_install_is_atomic_write_once_and_rejects_changed_file(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    reader, _source, _proc, _published = runtime_case(case)
    registration = reader.registration.document()
    registry = tmp_path / "registry"
    registry.mkdir(mode=0o755)
    assert install_runtime_registration(registration, registry, expected_owner_uid=os.getuid())
    assert not install_runtime_registration(registration, registry, expected_owner_uid=os.getuid())
    path = registry / (registration["runtime_registration_id"] + ".json")
    assert path.stat().st_mode & 0o777 == 0o600
    path.write_text("{}\n")
    path.chmod(0o600)
    with pytest.raises(ValueError, match="differs or is mutable"):
        install_runtime_registration(registration, registry, expected_owner_uid=os.getuid())
    assert not list(registry.glob(".*.tmp-*"))

    concurrent = tmp_path / "concurrent-registry"
    concurrent.mkdir(mode=0o755)
    with ThreadPoolExecutor(max_workers=6) as workers:
        results = list(
            workers.map(
                lambda _index: install_runtime_registration(
                    registration,
                    concurrent,
                    expected_owner_uid=os.getuid(),
                ),
                range(12),
            )
        )
    assert results.count(True) == 1 and results.count(False) == 11
    assert not list(concurrent.glob(".*.tmp-*"))


def test_installed_host_policy_verifier_binds_all_artifacts(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    reader, _source, _proc, _published = runtime_case(case)
    value, helper, gate = policy(tmp_path)
    registration = replace(reader.registration, authority_ref=value.authority_ref).document()
    root = tmp_path / "root"
    root.mkdir()
    write(root, RUNTIME_HELPER_PATH, helper, 0o755)
    write(root, RUNTIME_GATE_PATH, gate, 0o755)
    write(root, RUNTIME_SUDOERS_PATH, value.sudoers().encode(), 0o440)
    authorized = write(
        root,
        "/home/sky_inventory/.ssh/authorized_keys",
        value.authorized_keys().encode(),
        0o600,
    )
    authorized.parent.chmod(0o700)
    registry = root / RUNTIME_REGISTRY_PATH.removeprefix("/")
    registry.mkdir(parents=True)
    registry.chmod(0o755)
    assert install_runtime_registration(registration, registry, expected_owner_uid=os.getuid())
    receipt = verify_runtime_host_install(
        root,
        value,
        registration,
        root_uid=os.getuid(),
    )
    assert receipt["verification_id"].startswith("RHV-")
    assert receipt["mutation_authorized"] is False
    sudoers = root / RUNTIME_SUDOERS_PATH.removeprefix("/")
    sudoers.chmod(0o640)
    sudoers.write_text(value.sudoers() + "sky_inventory ALL=(ALL) NOPASSWD: ALL\n")
    sudoers.chmod(0o440)
    with pytest.raises(ValueError, match="content differs"):
        verify_runtime_host_install(root, value, registration, root_uid=os.getuid())
