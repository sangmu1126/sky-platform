"""Compile and verify the least-privilege remote runtime helper installation.

This module does not create users, edit sudoers or install SSH keys. It produces
canonical policy artifacts, verifies an existing filesystem image, and provides
write-once atomic installation for one content-addressed registration file.
"""

import base64
import hashlib
import json
import os
import re
import secrets
import stat
import struct
from dataclasses import dataclass
from pathlib import Path

from adapters.onprem.runtime_inventory import RUNTIME_HELPER_PATH
from adapters.runtime.workload_inventory import validate_linux_runtime_registration_document
from domain.environment_transition import _ref

RUNTIME_GATE_PATH = "/usr/local/bin/sky-runtime-inventory-ssh-gate"
RUNTIME_SUDOERS_PATH = "/etc/sudoers.d/sky-runtime-inventory"
RUNTIME_REGISTRY_PATH = "/etc/sky/runtime-inventory"


def _public_key(value):
    if not isinstance(value, str) or "\n" in value or "\r" in value or len(value.encode()) > 1024:
        raise ValueError("One bounded SSH public key required")
    parts = value.split()
    if len(parts) not in {2, 3} or parts[0] != "ssh-ed25519":
        raise ValueError("Dedicated Ed25519 runtime inventory key required")
    try:
        raw = base64.b64decode(parts[1], validate=True)
        first = struct.unpack(">I", raw[:4])[0]
        key_type = raw[4 : 4 + first]
        offset = 4 + first
        second = struct.unpack(">I", raw[offset : offset + 4])[0]
        key = raw[offset + 4 :]
    except (ValueError, struct.error):
        raise ValueError("Valid OpenSSH Ed25519 public key required") from None
    if key_type != b"ssh-ed25519" or second != 32 or len(key) != 32:
        raise ValueError("Valid OpenSSH Ed25519 public key required")
    canonical = parts[0] + " " + parts[1]
    return canonical, hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class RuntimeInventoryHostPolicy:
    authority_ref: str
    ssh_user: str
    ssh_uid: int
    public_key: str
    helper_sha256: str
    gate_sha256: str

    def __post_init__(self):
        _ref(self.authority_ref)
        if not re.fullmatch(r"ssh-[a-f0-9]{64}", self.authority_ref):
            raise ValueError("Pinned SSH runtime authority required")
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", self.ssh_user):
            raise ValueError("Dedicated runtime inventory SSH user required")
        if type(self.ssh_uid) is not int or not 1 <= self.ssh_uid <= 2**32 - 2:
            raise ValueError("Dedicated runtime inventory UID required")
        _public_key(self.public_key)
        for value in (self.helper_sha256, self.gate_sha256):
            if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
                raise ValueError("Pinned runtime helper artifact digests required")

    @property
    def public_key_sha256(self):
        return _public_key(self.public_key)[1]

    def authorized_keys(self):
        key, _digest = _public_key(self.public_key)
        options = (
            'restrict,command="'
            + RUNTIME_GATE_PATH
            + '",no-agent-forwarding,no-port-forwarding,no-pty,no-user-rc,no-X11-forwarding'
        )
        return options + " " + key + " sky-runtime-inventory\n"

    def sudoers(self):
        return (
            "Defaults:"
            + self.ssh_user
            + " env_reset,!setenv,secure_path=/usr/sbin:/usr/bin:/sbin:/bin\n"
            + self.ssh_user
            + " ALL=(root) NOPASSWD: sha256:"
            + self.helper_sha256
            + " "
            + RUNTIME_HELPER_PATH
            + " *\n"
        )

    def document(self):
        value = {
            "schema_version": 1,
            "profile": "pinned_runtime_inventory_host_v1",
            "authority_ref": self.authority_ref,
            "ssh_user": self.ssh_user,
            "ssh_uid": self.ssh_uid,
            "public_key_sha256": self.public_key_sha256,
            "helper_sha256": self.helper_sha256,
            "gate_sha256": self.gate_sha256,
            "helper_path": RUNTIME_HELPER_PATH,
            "gate_path": RUNTIME_GATE_PATH,
            "sudoers_path": RUNTIME_SUDOERS_PATH,
            "registry_path": RUNTIME_REGISTRY_PATH,
        }
        digest = hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        return {**value, "host_policy_id": "RHP-" + digest}


def _read_descriptor(descriptor, maximum):
    data = bytearray()
    while len(data) <= maximum:
        chunk = os.read(descriptor, min(65536, maximum + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    if len(data) > maximum:
        raise ValueError("Runtime inventory install artifact exceeds limit")
    return bytes(data)


def _registry_descriptor(registry_root, expected_owner_uid):
    root = Path(registry_root)
    if not root.is_absolute():
        raise ValueError("Absolute runtime registry path required")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in root.parts[1:]:
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
    except BaseException:
        os.close(descriptor)
        raise
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_owner_uid
        or metadata.st_mode & 0o022
    ):
        os.close(descriptor)
        raise ValueError("Immutable owner-bound runtime registry required")
    return descriptor


def install_runtime_registration(
    registration_document,
    registry_root=RUNTIME_REGISTRY_PATH,
    *,
    expected_owner_uid=0,
):
    """Install one hash-named registration atomically without replacement."""
    registration = validate_linux_runtime_registration_document(registration_document)
    if type(expected_owner_uid) is not int or not 0 <= expected_owner_uid <= 2**32 - 2:
        raise ValueError("Expected runtime registry owner required")
    data = (json.dumps(registration, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    filename = registration["runtime_registration_id"] + ".json"
    directory = _registry_descriptor(registry_root, expected_owner_uid)

    def existing():
        descriptor = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            metadata = os.fstat(descriptor)
            current = _read_descriptor(descriptor, 256 * 1024)
        finally:
            os.close(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_owner_uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or current != data
        ):
            raise ValueError("Existing runtime registration differs or is mutable")
        return False

    try:
        try:
            return existing()
        except FileNotFoundError:
            pass
        temporary = "." + filename + ".tmp-" + secrets.token_hex(12)
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        try:
            written = 0
            while written < len(data):
                count = os.write(descriptor, data[written:])
                if count <= 0:
                    raise OSError("Runtime registration write stopped")
                written += count
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            if metadata.st_uid != expected_owner_uid or stat.S_IMODE(metadata.st_mode) != 0o600:
                raise ValueError("New runtime registration ownership differs")
        finally:
            os.close(descriptor)
        try:
            os.link(
                temporary,
                filename,
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )
            os.unlink(temporary, dir_fd=directory)
            os.fsync(directory)
            return True
        except FileExistsError:
            os.unlink(temporary, dir_fd=directory)
            return existing()
        except BaseException:
            os.unlink(temporary, dir_fd=directory)
            raise
    finally:
        os.close(directory)


def _installed_path(root, absolute_path):
    relative = absolute_path.removeprefix("/")
    path = Path(root) / relative
    current = path
    while current != Path(root):
        if current.is_symlink() or Path(root) not in current.parents:
            raise ValueError("Installed runtime artifact path cannot contain links")
        current = current.parent
    return path


def _installed_file(root, absolute_path, *, owner_uid, mode, maximum=1024 * 1024):
    path = _installed_path(root, absolute_path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        data = _read_descriptor(descriptor, maximum)
    finally:
        os.close(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise ValueError("Installed runtime artifact ownership or mode differs")
    return data


def _installed_directory(root, absolute_path, *, owner_uid, mode):
    path = _installed_path(root, absolute_path)
    if not path.is_dir():
        raise ValueError("Plain installed runtime directory required")
    metadata = path.stat()
    if metadata.st_uid != owner_uid or stat.S_IMODE(metadata.st_mode) != mode:
        raise ValueError("Installed runtime directory ownership or mode differs")


def verify_runtime_host_install(root, policy, registration_document, *, root_uid=0):
    if not isinstance(policy, RuntimeInventoryHostPolicy):
        raise TypeError("Typed runtime host policy required")
    registration = validate_linux_runtime_registration_document(registration_document)
    root = Path(root)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ValueError("Plain absolute runtime host root required")
    if registration["authority_ref"] != policy.authority_ref:
        raise ValueError("Runtime registration authority differs from host policy")
    _installed_directory(
        root,
        "/home/" + policy.ssh_user + "/.ssh",
        owner_uid=policy.ssh_uid,
        mode=0o700,
    )
    _installed_directory(root, RUNTIME_REGISTRY_PATH, owner_uid=root_uid, mode=0o755)
    helper = _installed_file(root, RUNTIME_HELPER_PATH, owner_uid=root_uid, mode=0o755)
    gate = _installed_file(root, RUNTIME_GATE_PATH, owner_uid=root_uid, mode=0o755)
    sudoers = _installed_file(root, RUNTIME_SUDOERS_PATH, owner_uid=root_uid, mode=0o440)
    authorized = _installed_file(
        root,
        "/home/" + policy.ssh_user + "/.ssh/authorized_keys",
        owner_uid=policy.ssh_uid,
        mode=0o600,
    )
    registration_path = RUNTIME_REGISTRY_PATH + "/" + registration["runtime_registration_id"] + ".json"
    registered = _installed_file(root, registration_path, owner_uid=root_uid, mode=0o600)
    expected_registration = (
        json.dumps(registration, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()
    if (
        hashlib.sha256(helper).hexdigest() != policy.helper_sha256
        or hashlib.sha256(gate).hexdigest() != policy.gate_sha256
        or sudoers != policy.sudoers().encode()
        or authorized != policy.authorized_keys().encode()
        or registered != expected_registration
    ):
        raise ValueError("Installed runtime host policy content differs")
    value = {
        "schema_version": 1,
        "profile": "verified_runtime_inventory_host_v1",
        "host_policy_id": policy.document()["host_policy_id"],
        "runtime_registration_id": registration["runtime_registration_id"],
        "authority_ref": policy.authority_ref,
        "mutation_authorized": False,
    }
    digest = hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    return {**value, "verification_id": "RHV-" + digest}
