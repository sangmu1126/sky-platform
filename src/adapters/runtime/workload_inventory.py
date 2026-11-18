"""Bounded Linux /proc evidence for a registered workload inventory.

The collector reads only identities, socket tables and file-descriptor metadata
for explicitly registered PIDs. It never signals a process, opens a network
connection or executes a command. Intermittent dependencies that are not open at
the sampling instant remain blocked rather than being inferred as absent.
"""

import hashlib
import ipaddress
import json
import os
import re
import socket
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path, PurePosixPath

from adapters.runtime.provider_identity import (
    PROVIDER_IDENTITY_CATEGORIES,
    ProviderIdentityEvidence,
)
from adapters.source.workload_inventory import RegisteredStaticSourceInventory
from domain.environment_transition import _ref, _time
from domain.workload_inventory import (
    DEPENDENCY_CATEGORIES,
    ObservedWorkloadDependency,
    WorkloadInventorySnapshot,
)
from ports.workload_inventory import WorkloadInventoryUnavailable


def _absolute_path(value, label):
    if (
        not isinstance(value, str)
        or not 1 <= len(value.encode()) <= 1024
        or "\x00" in value
        or not PurePosixPath(value).is_absolute()
        or ".." in PurePosixPath(value).parts
    ):
        raise ValueError(f"Registered absolute {label} required")


@dataclass(frozen=True)
class RegisteredLinuxProcess:
    component_ref: str
    pid: int
    start_time_ticks: int
    uid: int
    executable: str
    listener_ports: tuple[int, ...] = ()
    process_ref: str = ""

    def __post_init__(self):
        _ref(self.component_ref)
        if not self.process_ref:
            object.__setattr__(self, "process_ref", self.component_ref)
        _ref(self.process_ref)
        if type(self.pid) is not int or not 1 <= self.pid <= 2**31 - 1:
            raise ValueError("Registered Linux PID required")
        if type(self.start_time_ticks) is not int or self.start_time_ticks < 1:
            raise ValueError("Pinned Linux process start time required")
        if type(self.uid) is not int or not 0 <= self.uid <= 2**32 - 2:
            raise ValueError("Registered Linux process UID required")
        _absolute_path(self.executable, "executable path")
        if (
            not isinstance(self.listener_ports, tuple)
            or tuple(sorted(self.listener_ports)) != self.listener_ports
            or len(set(self.listener_ports)) != len(self.listener_ports)
            or any(type(port) is not int or not 1 <= port <= 65535 for port in self.listener_ports)
        ):
            raise ValueError("Canonical registered listener ports required")


@dataclass(frozen=True)
class RegisteredLinuxDependencyProbe:
    logical_ref: str
    component_ref: str
    kind: str
    address: str = ""
    port: int = 0
    path_prefix: str = ""

    def __post_init__(self):
        _ref(self.logical_ref)
        _ref(self.component_ref)
        if self.kind == "tcp":
            try:
                canonical = str(ipaddress.ip_address(self.address))
            except ValueError:
                raise ValueError("Canonical registered dependency IP required") from None
            if canonical != self.address or type(self.port) is not int or not 1 <= self.port <= 65535:
                raise ValueError("Canonical registered dependency TCP endpoint required")
            if self.path_prefix:
                raise ValueError("TCP dependency cannot register a file path")
        elif self.kind == "file":
            _absolute_path(self.path_prefix, "dependency path prefix")
            if self.address or self.port:
                raise ValueError("File dependency cannot register a TCP endpoint")
        elif self.kind == "process_memory":
            if self.address or self.port or self.path_prefix:
                raise ValueError("Process-memory dependency takes no external target")
        else:
            raise ValueError("Bounded Linux dependency probe kind required")


@dataclass(frozen=True)
class RegisteredLinuxRuntimeInventory:
    source: RegisteredStaticSourceInventory
    endpoint: str
    boot_id: str
    processes: tuple[RegisteredLinuxProcess, ...]
    probes: tuple[RegisteredLinuxDependencyProbe, ...]
    authority_ref: str = "local-proc"
    provider_identity_registration_id: str = ""

    def __post_init__(self):
        if not isinstance(self.source, RegisteredStaticSourceInventory):
            raise TypeError("Registered static source inventory required")
        if self.endpoint not in {"source", "target"}:
            raise ValueError("Registered runtime endpoint required")
        if not re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", self.boot_id):
            raise ValueError("Pinned Linux boot ID required")
        _ref(self.authority_ref)
        components = {value[0] for value in self.source.inventory.component_roles}
        if (
            not isinstance(self.processes, tuple)
            or not 1 <= len(self.processes) <= 256
            or tuple(sorted(self.processes, key=lambda item: (item.component_ref, item.process_ref)))
            != self.processes
            or {value.component_ref for value in self.processes} != components
            or len({value.process_ref for value in self.processes}) != len(self.processes)
            or len({value.pid for value in self.processes}) != len(self.processes)
        ):
            raise ValueError("Canonical registered Linux process replicas required")
        if (
            not isinstance(self.probes, tuple)
            or tuple(sorted(self.probes, key=lambda item: (item.logical_ref, item.component_ref)))
            != self.probes
            or len({(value.logical_ref, value.component_ref) for value in self.probes}) != len(self.probes)
        ):
            raise ValueError("Canonical registered Linux dependency probes required")
        policies = {value.logical_ref: value for value in self.source.inventory.dependency_policies}
        requires_provider_identity = any(
            value.category in PROVIDER_IDENTITY_CATEGORIES for value in policies.values()
        )
        if requires_provider_identity != bool(
            re.fullmatch(r"PIR-[a-f0-9]{64}", self.provider_identity_registration_id)
        ):
            raise ValueError("Provider dependencies require bound resource identity registration")
        expected = {
            (policy.logical_ref, component)
            for policy in policies.values()
            for component in policy.component_refs
        }
        if {(value.logical_ref, value.component_ref) for value in self.probes} != expected:
            raise ValueError("Every registered dependency component needs one runtime probe")
        for probe in self.probes:
            policy = policies[probe.logical_ref]
            allowed = (
                {"process_memory"}
                if policy.category == "session_state"
                else {"file"}
                if policy.category == "filesystem"
                else {"tcp"}
            )
            if probe.kind not in allowed:
                raise ValueError("Runtime probe kind differs from dependency category")

    @property
    def inventory(self):
        return self.source.inventory

    def document(self):
        value = {
            "schema_version": 1,
            "profile": "registered_linux_proc_workload_v1",
            "source_registration_id": self.source.document()["source_registration_id"],
            "inventory_id": self.inventory.document()["inventory_id"],
            "endpoint": self.endpoint,
            "boot_id": self.boot_id,
            "authority_ref": self.authority_ref,
            "provider_identity_registration_id": self.provider_identity_registration_id,
            "processes": [asdict(value) for value in self.processes],
            "probes": [asdict(value) for value in self.probes],
        }
        digest = hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        return {**value, "runtime_registration_id": "WRR-" + digest}


def validate_linux_runtime_registration_document(document):
    """Validate the root-owned registration consumed by the remote helper."""
    try:
        raw = json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False)
        fields = {
            "schema_version",
            "profile",
            "source_registration_id",
            "inventory_id",
            "endpoint",
            "boot_id",
            "authority_ref",
            "provider_identity_registration_id",
            "processes",
            "probes",
            "runtime_registration_id",
        }
        if not isinstance(document, dict) or set(document) != fields or len(raw.encode()) > 256 * 1024:
            raise ValueError("Bounded Linux runtime registration document required")
        if (
            document["schema_version"] != 1
            or document["profile"] != "registered_linux_proc_workload_v1"
            or not re.fullmatch(r"WSR-[a-f0-9]{64}", document["source_registration_id"])
            or not re.fullmatch(r"WIR-[a-f0-9]{64}", document["inventory_id"])
            or document["endpoint"] not in {"source", "target"}
            or not re.fullmatch(
                r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
                document["boot_id"],
            )
        ):
            raise ValueError("Invalid Linux runtime registration identity")
        _ref(document["authority_ref"])
        if document["provider_identity_registration_id"] and not re.fullmatch(
            r"PIR-[a-f0-9]{64}", document["provider_identity_registration_id"]
        ):
            raise ValueError("Invalid provider identity registration")
        processes = document["processes"]
        probes = document["probes"]
        if not isinstance(processes, list) or not 1 <= len(processes) <= 256:
            raise ValueError("Bounded registered Linux processes required")
        typed_processes = []
        for value in processes:
            if not isinstance(value, dict) or set(value) != {
                "component_ref",
                "process_ref",
                "pid",
                "start_time_ticks",
                "uid",
                "executable",
                "listener_ports",
            }:
                raise ValueError("Invalid registered Linux process document")
            typed_processes.append(
                RegisteredLinuxProcess(
                    value["component_ref"],
                    value["pid"],
                    value["start_time_ticks"],
                    value["uid"],
                    value["executable"],
                    tuple(value["listener_ports"]),
                    value["process_ref"],
                )
            )
        if (
            tuple(sorted(typed_processes, key=lambda item: (item.component_ref, item.process_ref)))
            != tuple(typed_processes)
            or len({value.process_ref for value in typed_processes}) != len(typed_processes)
            or len({value.pid for value in typed_processes}) != len(typed_processes)
        ):
            raise ValueError("Canonical registered Linux process replicas required")
        if not isinstance(probes, list) or len(probes) > 128:
            raise ValueError("Bounded registered Linux probes required")
        typed_probes = []
        for value in probes:
            if not isinstance(value, dict) or set(value) != {
                "logical_ref",
                "component_ref",
                "kind",
                "address",
                "port",
                "path_prefix",
            }:
                raise ValueError("Invalid registered Linux probe document")
            typed_probes.append(RegisteredLinuxDependencyProbe(**value))
        components = {item.component_ref for item in typed_processes}
        if (
            tuple(sorted(typed_probes, key=lambda item: (item.logical_ref, item.component_ref)))
            != tuple(typed_probes)
            or len({(value.logical_ref, value.component_ref) for value in typed_probes}) != len(typed_probes)
            or any(value.component_ref not in components for value in typed_probes)
        ):
            raise ValueError("Canonical registered Linux probes required")
        unsigned = {key: value for key, value in document.items() if key != "runtime_registration_id"}
        digest = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        if document["runtime_registration_id"] != "WRR-" + digest:
            raise ValueError("Linux runtime registration identity changed")
        return json.loads(raw)
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        raise ValueError("Invalid Linux runtime registration document") from None


def _read_text(path, maximum=256 * 1024):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Plain proc metadata file required")
    with path.open("rb") as source:
        data = source.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("Proc metadata exceeds inventory limits")
    try:
        return data.decode()
    except UnicodeDecodeError:
        raise ValueError("Proc metadata is not UTF-8") from None


def _process_identity(directory):
    stat = _read_text(directory / "stat", 8192).strip()
    close = stat.rfind(")")
    fields = stat[close + 1 :].split() if close > 0 else []
    pid = stat[:close].split("(", 1)[0].strip()
    if not pid.isdigit() or int(pid) != int(directory.name) or len(fields) < 20:
        raise ValueError("Invalid proc process stat")
    start_time = int(fields[19])
    uid_lines = [
        line for line in _read_text(directory / "status", 65536).splitlines() if line.startswith("Uid:")
    ]
    if len(uid_lines) != 1 or len(uid_lines[0].split()) != 5:
        raise ValueError("Invalid proc process UID")
    uids = tuple(int(value) for value in uid_lines[0].split()[1:])
    if len(set(uids)) != 1:
        raise ValueError("Runtime process changed UID")
    executable = directory / "exe"
    if not executable.is_symlink():
        raise ValueError("Pinned proc executable link required")
    target = os.readlink(executable)
    if target.endswith(" (deleted)"):
        raise ValueError("Deleted runtime executable is not trusted")
    return start_time, uids[0], target


def _tcp_address(value, family):
    raw = bytes.fromhex(value)
    if family == socket.AF_INET:
        raw = raw[::-1]
    else:
        raw = b"".join(raw[index : index + 4][::-1] for index in range(0, 16, 4))
    return str(ipaddress.ip_address(socket.inet_ntop(family, raw)))


def _tcp_table(path, family):
    rows = {}
    lines = _read_text(path).splitlines()
    if not lines or "local_address" not in lines[0]:
        raise ValueError("Invalid proc TCP table")
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 10:
            raise ValueError("Invalid proc TCP socket")
        local_address, local_port = fields[1].split(":")
        remote_address, remote_port = fields[2].split(":")
        inode = int(fields[9])
        if inode:
            rows[inode] = (
                _tcp_address(local_address, family),
                int(local_port, 16),
                _tcp_address(remote_address, family),
                int(remote_port, 16),
                fields[3],
            )
        if len(rows) > 4096:
            raise ValueError("Proc TCP table exceeds inventory limits")
    return rows


def _fd_inventory(directory):
    descriptors = directory / "fd"
    if descriptors.is_symlink() or not descriptors.is_dir():
        raise ValueError("Plain proc descriptor directory required")
    sockets, writable = set(), set()
    entries = sorted(descriptors.iterdir(), key=lambda value: int(value.name))
    if len(entries) > 4096 or any(not value.name.isdigit() or not value.is_symlink() for value in entries):
        raise ValueError("Bounded proc descriptors required")
    for descriptor in entries:
        target = os.readlink(descriptor)
        match = re.fullmatch(r"socket:\[(\d+)\]", target)
        if match:
            sockets.add(int(match.group(1)))
            continue
        if not target.startswith("/") or target.endswith(" (deleted)"):
            continue
        lines = _read_text(directory / "fdinfo" / descriptor.name, 8192).splitlines()
        flags = [line.split()[1] for line in lines if line.startswith("flags:")]
        if len(flags) != 1:
            raise ValueError("Proc descriptor flags unavailable")
        if int(flags[0], 8) & os.O_ACCMODE in {os.O_WRONLY, os.O_RDWR}:
            writable.add(target)
    return sockets, writable


def _under(path, prefix):
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def collect_linux_proc_observation(registration_document, proc_root, *, clock):
    """Collect bounded raw facts for a root-owned runtime registration."""
    registration = validate_linux_runtime_registration_document(registration_document)
    root = Path(proc_root)
    if root.is_symlink() or not root.is_dir() or not callable(clock):
        raise ValueError("Pinned proc filesystem and clock required")
    boot_path = root / "sys/kernel/random/boot_id"
    boot_before = _read_text(boot_path, 128).strip()
    if boot_before != registration["boot_id"]:
        raise ValueError("Linux boot identity changed")
    observations = []
    for value in registration["processes"]:
        process = RegisteredLinuxProcess(
            value["component_ref"],
            value["pid"],
            value["start_time_ticks"],
            value["uid"],
            value["executable"],
            tuple(value["listener_ports"]),
            value["process_ref"],
        )
        directory = root / str(process.pid)
        identity = _process_identity(directory)
        if identity != (process.start_time_ticks, process.uid, process.executable):
            raise ValueError("Registered Linux process identity changed")
        sockets, writable = _fd_inventory(directory)
        tcp = _tcp_table(directory / "net/tcp", socket.AF_INET)
        tcp6 = _tcp_table(directory / "net/tcp6", socket.AF_INET6)
        network = {inode: item for inode, item in {**tcp, **tcp6}.items() if inode in sockets}
        unknown_sockets = sockets - set(tcp) - set(tcp6)
        connections = sorted(
            (
                {
                    "local_port": item[1],
                    "remote_address": item[2],
                    "remote_port": item[3],
                    "state": item[4],
                }
                for item in network.values()
            ),
            key=lambda item: (
                item["local_port"],
                item["remote_address"],
                item["remote_port"],
                item["state"],
            ),
        )
        listeners = sorted({item["local_port"] for item in connections if item["state"] == "0A"})
        if _process_identity(directory) != identity:
            raise ValueError("Process changed during runtime observation")
        observations.append(
            {
                "component_ref": process.component_ref,
                "process_ref": process.process_ref,
                "pid": process.pid,
                "start_time_ticks": process.start_time_ticks,
                "uid": process.uid,
                "executable": process.executable,
                "listener_ports": listeners,
                "connections": connections,
                "writable_paths": sorted(writable),
                "socket_count": len(sockets),
                "unknown_socket_count": len(unknown_sockets),
            }
        )
    if _read_text(boot_path, 128).strip() != boot_before:
        raise ValueError("Boot changed during runtime observation")
    observed = clock()
    _time(observed)
    document = {
        "schema_version": 1,
        "profile": "registered_linux_proc_observation_v1",
        "runtime_registration_id": registration["runtime_registration_id"],
        "authority_ref": registration["authority_ref"],
        "boot_id": registration["boot_id"],
        "observed_at": observed.isoformat(),
        "processes": observations,
    }
    digest = hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    return {**document, "observation_id": "WRO-" + digest}


def validate_linux_proc_observation(registration, document):
    try:
        if not isinstance(registration, RegisteredLinuxRuntimeInventory):
            raise TypeError("Registered Linux runtime inventory required")
        raw = json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False)
        fields = {
            "schema_version",
            "profile",
            "runtime_registration_id",
            "authority_ref",
            "boot_id",
            "observed_at",
            "processes",
            "observation_id",
        }
        registered = registration.document()
        if (
            not isinstance(document, dict)
            or set(document) != fields
            or len(raw.encode()) > 512 * 1024
            or document["schema_version"] != 1
            or document["profile"] != "registered_linux_proc_observation_v1"
            or document["runtime_registration_id"] != registered["runtime_registration_id"]
            or document["authority_ref"] != registered["authority_ref"]
            or document["boot_id"] != registered["boot_id"]
        ):
            raise ValueError("Linux proc observation differs from registration")
        observed = datetime.fromisoformat(document["observed_at"])
        _time(observed)
        expected = {value.process_ref: value for value in registration.processes}
        processes = document["processes"]
        if (
            not isinstance(processes, list)
            or any(not isinstance(value, dict) for value in processes)
            or [value.get("process_ref") for value in processes] != list(expected)
        ):
            raise ValueError("Canonical Linux proc observations required")
        process_fields = {
            "component_ref",
            "process_ref",
            "pid",
            "start_time_ticks",
            "uid",
            "executable",
            "listener_ports",
            "connections",
            "writable_paths",
            "socket_count",
            "unknown_socket_count",
        }
        connection_fields = {"local_port", "remote_address", "remote_port", "state"}
        for value in processes:
            process = expected[value["process_ref"]]
            connections = value["connections"]
            writable = value["writable_paths"]
            if isinstance(writable, list):
                for path in writable:
                    _absolute_path(path, "observed writable path")
            if (
                set(value) != process_fields
                or value["component_ref"] != process.component_ref
                or (value["pid"], value["start_time_ticks"], value["uid"], value["executable"])
                != (process.pid, process.start_time_ticks, process.uid, process.executable)
                or not isinstance(connections, list)
                or len(connections) > 4096
                or not isinstance(writable, list)
                or len(writable) > 4096
                or writable != sorted(set(writable))
                or type(value["socket_count"]) is not int
                or not len(connections) <= value["socket_count"] <= 4096
                or type(value["unknown_socket_count"]) is not int
                or not 0 <= value["unknown_socket_count"] <= value["socket_count"]
            ):
                raise ValueError("Invalid Linux proc process observation")
            keys = []
            for connection in connections:
                if not isinstance(connection, dict) or set(connection) != connection_fields:
                    raise ValueError("Invalid Linux proc connection observation")
                address = str(ipaddress.ip_address(connection["remote_address"]))
                key = (
                    connection["local_port"],
                    address,
                    connection["remote_port"],
                    connection["state"],
                )
                if (
                    address != connection["remote_address"]
                    or type(connection["local_port"]) is not int
                    or not 0 <= connection["local_port"] <= 65535
                    or type(connection["remote_port"]) is not int
                    or not 0 <= connection["remote_port"] <= 65535
                    or not isinstance(connection["state"], str)
                    or not re.fullmatch(r"[0-9A-F]{2}", connection["state"])
                ):
                    raise ValueError("Invalid Linux proc connection value")
                keys.append(key)
            if keys != sorted(set(keys)):
                raise ValueError("Canonical Linux proc connections required")
            listeners = sorted({item["local_port"] for item in connections if item["state"] == "0A"})
            if value["listener_ports"] != listeners:
                raise ValueError("Linux proc listener evidence differs from sockets")
        unsigned = {key: value for key, value in document.items() if key != "observation_id"}
        digest = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        if document["observation_id"] != "WRO-" + digest:
            raise ValueError("Linux proc observation identity changed")
        return json.loads(raw)
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        raise ValueError("Invalid Linux proc observation") from None


def assess_linux_proc_observation(registration, observation, *, now, provider_evidence=None):
    observation = validate_linux_proc_observation(registration, observation)
    _time(now)
    observed = datetime.fromisoformat(observation["observed_at"])
    if not 0 <= (now - observed).total_seconds() <= 30:
        raise ValueError("Fresh Linux runtime observation required")
    observed_processes = {value["process_ref"]: value for value in observation["processes"]}
    probes = {(value.logical_ref, value.component_ref): value for value in registration.probes}
    replica_refs = {
        component: {
            process.process_ref for process in registration.processes if process.component_ref == component
        }
        for component in {process.component_ref for process in registration.processes}
    }
    matched_replicas = {key: set() for key in probes}
    blockers = []
    provider_report_id = ""
    if registration.provider_identity_registration_id:
        if (
            isinstance(provider_evidence, ProviderIdentityEvidence)
            and provider_evidence.registration_id == registration.provider_identity_registration_id
            and 0 <= (observed - provider_evidence.observed_at).total_seconds() <= 30
            and provider_evidence.expires_at >= observed
        ):
            provider_report_id = provider_evidence.report_id
        else:
            blockers.append("provider_identity_evidence_unavailable")
    elif provider_evidence is not None:
        blockers.append("unregistered_provider_identity_evidence")
    process_reports = []
    for process in registration.processes:
        facts = observed_processes[process.process_ref]
        connections = facts["connections"]
        writable = facts["writable_paths"]
        if facts["listener_ports"] != list(process.listener_ports):
            blockers.append("listener_registration_changed:" + process.process_ref)
        component_probes = [
            value for value in registration.probes if value.component_ref == process.component_ref
        ]
        tcp_probes = [value for value in component_probes if value.kind == "tcp"]
        file_probes = [value for value in component_probes if value.kind == "file"]
        for probe in component_probes:
            found = probe.kind == "process_memory"
            if probe.kind == "tcp":
                found = any(
                    value["state"] == "01"
                    and (value["remote_address"], value["remote_port"]) == (probe.address, probe.port)
                    for value in connections
                )
            elif probe.kind == "file":
                found = any(_under(path, probe.path_prefix) for path in writable)
            if found:
                matched_replicas[(probe.logical_ref, probe.component_ref)].add(process.process_ref)
            else:
                blockers.append(
                    "registered_runtime_dependency_unobserved:"
                    + probe.logical_ref
                    + ":"
                    + probe.component_ref
                    + ":"
                    + process.process_ref
                )
        unexpected_tcp = sum(
            not (
                (value["state"] == "0A" and value["local_port"] in process.listener_ports)
                or (value["state"] == "01" and value["local_port"] in process.listener_ports)
                or (
                    value["state"] == "01"
                    and any(
                        (value["remote_address"], value["remote_port"]) == (probe.address, probe.port)
                        for probe in tcp_probes
                    )
                )
            )
            for value in connections
        )
        unexpected_files = sum(
            not any(_under(path, probe.path_prefix) for probe in file_probes) for path in writable
        )
        if unexpected_tcp:
            blockers.append("unregistered_runtime_tcp:" + process.process_ref)
        if facts["unknown_socket_count"]:
            blockers.append("unclassified_runtime_socket:" + process.process_ref)
        if unexpected_files:
            blockers.append("unregistered_runtime_writer:" + process.process_ref)
        process_reports.append(
            {
                "component_ref": process.component_ref,
                "process_ref": process.process_ref,
                "pid": process.pid,
                "start_time_ticks": process.start_time_ticks,
                "uid": process.uid,
                "executable": process.executable,
                "listener_ports": facts["listener_ports"],
                "socket_count": facts["socket_count"],
                "writable_file_count": len(writable),
                "unexpected_tcp_count": unexpected_tcp,
                "unexpected_socket_count": facts["unknown_socket_count"],
                "unexpected_writer_count": unexpected_files,
            }
        )
    matched = {
        key for key, observed_refs in matched_replicas.items() if observed_refs == replica_refs[key[1]]
    }
    if matched != set(probes):
        blockers.append("runtime_probe_coverage_incomplete")
    value = {
        "schema_version": 1,
        "profile": "registered_linux_proc_workload_v1",
        "runtime_registration_id": registration.document()["runtime_registration_id"],
        "inventory_id": registration.inventory.document()["inventory_id"],
        "endpoint": registration.endpoint,
        "boot_id": registration.boot_id,
        "evaluated_at": observed.isoformat(),
        "expires_at": (observed + timedelta(seconds=registration.inventory.max_age_seconds)).isoformat(),
        "status": "verified" if not blockers else "blocked",
        "blockers": sorted(set(blockers)),
        "processes": process_reports,
        "observed_probes": [list(value) for value in sorted(matched)],
        "provider_identity_report_id": provider_report_id,
        "execution_authorized": False,
    }
    digest = hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    return {**value, "report_id": "WRI-" + digest}, observed


def _snapshot(registration, evidence_refs, observed):
    inventory = registration.inventory
    endpoint = registration.endpoint
    dependencies = tuple(
        ObservedWorkloadDependency(
            policy.logical_ref,
            policy.category,
            policy.component_refs,
            policy.access_mode,
            policy.source_location_ref if endpoint == "source" else policy.target_location_ref,
        )
        for policy in inventory.dependency_policies
    )
    present = {value.category for value in dependencies}
    return WorkloadInventorySnapshot(
        inventory.document()["inventory_id"],
        inventory.scope,
        endpoint,
        inventory.component_roles,
        tuple(
            (category, "present" if category in present else "verified_absent")
            for category in DEPENDENCY_CATEGORIES
        ),
        dependencies,
        tuple(sorted(evidence_refs)),
        observed,
        observed + timedelta(seconds=inventory.max_age_seconds),
    )


class LinuxProcWorkloadInventoryReader:
    def __init__(self, registration, proc_root, publisher, *, clock, provider_identity_reader=None):
        if not isinstance(registration, RegisteredLinuxRuntimeInventory):
            raise TypeError("Registered Linux runtime inventory required")
        if not callable(getattr(publisher, "publish", None)) or not callable(clock):
            raise TypeError("Runtime evidence publisher and clock required")
        self.registration = registration
        self.proc_root = Path(proc_root)
        self.publisher = publisher
        self.clock = clock
        self.provider_identity_reader = provider_identity_reader

    def collect(self, inventory, endpoint):
        if inventory != self.registration.inventory or endpoint != self.registration.endpoint:
            raise ValueError("Linux runtime inventory registration changed")
        try:
            report, observed = self._inspect()
            evidence_ref = self.publisher.publish(json.loads(json.dumps(report)))
            if evidence_ref != report["report_id"] or report["status"] != "verified":
                raise ValueError("Linux runtime inventory was not durably verified")
            evidence_refs = [evidence_ref]
            if report["provider_identity_report_id"]:
                evidence_refs.append(report["provider_identity_report_id"])
            return _snapshot(self.registration, evidence_refs, observed)
        except Exception:  # noqa: BLE001 -- proc diagnostics and host paths remain private
            raise WorkloadInventoryUnavailable("Registered Linux runtime inventory unavailable") from None

    def _inspect(self):
        provider_evidence = None
        if self.registration.provider_identity_registration_id:
            try:
                provider_evidence = self.provider_identity_reader.collect(
                    self.registration.inventory, self.registration.endpoint
                )
            except Exception:  # noqa: BLE001 -- provider diagnostics remain private
                provider_evidence = None
        observation = collect_linux_proc_observation(
            self.registration.document(), self.proc_root, clock=self.clock
        )
        return assess_linux_proc_observation(
            self.registration,
            observation,
            now=self.clock(),
            provider_evidence=provider_evidence,
        )


class RemoteLinuxWorkloadInventoryReader:
    """Evaluate a pinned remote helper observation under the same local policy."""

    def __init__(self, registration, transport, publisher, *, clock, provider_identity_reader=None):
        if not isinstance(registration, RegisteredLinuxRuntimeInventory):
            raise TypeError("Registered Linux runtime inventory required")
        if not all(
            callable(value)
            for value in (getattr(transport, "observe", None), getattr(publisher, "publish", None), clock)
        ):
            raise TypeError("Pinned runtime transport, publisher and clock required")
        self.registration = registration
        self.transport = transport
        self.publisher = publisher
        self.clock = clock
        self.provider_identity_reader = provider_identity_reader

    def collect(self, inventory, endpoint):
        if inventory != self.registration.inventory or endpoint != self.registration.endpoint:
            raise ValueError("Remote Linux runtime inventory registration changed")
        try:
            provider_evidence = None
            if self.registration.provider_identity_registration_id:
                try:
                    provider_evidence = self.provider_identity_reader.collect(
                        self.registration.inventory, self.registration.endpoint
                    )
                except Exception:  # noqa: BLE001 -- provider diagnostics remain private
                    provider_evidence = None
            observation = self.transport.observe(self.registration)
            report, observed = assess_linux_proc_observation(
                self.registration,
                observation,
                now=self.clock(),
                provider_evidence=provider_evidence,
            )
            evidence_ref = self.publisher.publish(json.loads(json.dumps(report)))
            if evidence_ref != report["report_id"] or report["status"] != "verified":
                raise ValueError("Remote Linux runtime inventory was not durably verified")
            evidence_refs = [evidence_ref]
            if report["provider_identity_report_id"]:
                evidence_refs.append(report["provider_identity_report_id"])
            return _snapshot(self.registration, evidence_refs, observed)
        except Exception:  # noqa: BLE001 -- remote diagnostics and host paths remain private
            raise WorkloadInventoryUnavailable("Registered remote runtime inventory unavailable") from None


def validate_linux_runtime_inventory_report(registration, document):
    try:
        if not isinstance(registration, RegisteredLinuxRuntimeInventory):
            raise TypeError("Registered Linux runtime inventory required")
        raw = json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(raw.encode()) > 512 * 1024:
            raise ValueError("Bounded Linux runtime report required")
        fields = {
            "schema_version",
            "profile",
            "runtime_registration_id",
            "inventory_id",
            "endpoint",
            "boot_id",
            "evaluated_at",
            "expires_at",
            "status",
            "blockers",
            "processes",
            "observed_probes",
            "provider_identity_report_id",
            "execution_authorized",
            "report_id",
        }
        registered = registration.document()
        if (
            not isinstance(document, dict)
            or set(document) != fields
            or document["schema_version"] != 1
            or document["profile"] != registered["profile"]
            or document["runtime_registration_id"] != registered["runtime_registration_id"]
            or document["inventory_id"] != registered["inventory_id"]
            or document["endpoint"] != registered["endpoint"]
            or document["boot_id"] != registered["boot_id"]
            or document["execution_authorized"] is not False
            or document["status"] not in {"blocked", "verified"}
        ):
            raise ValueError("Linux runtime report differs from registration")
        provider_report_id = document["provider_identity_report_id"]
        if registration.provider_identity_registration_id:
            if provider_report_id and not re.fullmatch(r"WPI-[a-f0-9]{64}", provider_report_id):
                raise ValueError("Invalid provider identity evidence reference")
            if document["status"] == "verified" and not provider_report_id:
                raise ValueError("Verified runtime report requires provider identity evidence")
        elif provider_report_id:
            raise ValueError("Unregistered provider identity evidence reference")
        evaluated = datetime.fromisoformat(document["evaluated_at"])
        expires = datetime.fromisoformat(document["expires_at"])
        _time(evaluated)
        _time(expires)
        if expires != evaluated + timedelta(seconds=registration.inventory.max_age_seconds):
            raise ValueError("Linux runtime evidence lifetime changed")
        blockers = document["blockers"]
        if (
            not isinstance(blockers, list)
            or blockers != sorted(set(blockers))
            or any(not isinstance(value, str) or not 1 <= len(value) <= 1200 for value in blockers)
            or (document["status"] == "verified") != (not blockers)
        ):
            raise ValueError("Invalid Linux runtime blockers")
        expected_processes = {value.process_ref: value for value in registration.processes}
        processes = document["processes"]
        if (
            not isinstance(processes, list)
            or any(not isinstance(value, dict) for value in processes)
            or [value.get("process_ref") for value in processes] != list(expected_processes)
        ):
            raise ValueError("Canonical Linux runtime processes required")
        process_fields = {
            "component_ref",
            "process_ref",
            "pid",
            "start_time_ticks",
            "uid",
            "executable",
            "listener_ports",
            "socket_count",
            "writable_file_count",
            "unexpected_tcp_count",
            "unexpected_socket_count",
            "unexpected_writer_count",
        }
        for value in processes:
            registered_process = expected_processes[value["process_ref"]]
            if (
                set(value) != process_fields
                or value["component_ref"] != registered_process.component_ref
                or (value["pid"], value["start_time_ticks"], value["uid"], value["executable"])
                != (
                    registered_process.pid,
                    registered_process.start_time_ticks,
                    registered_process.uid,
                    registered_process.executable,
                )
                or not isinstance(value["listener_ports"], list)
                or value["listener_ports"] != sorted(set(value["listener_ports"]))
                or any(type(port) is not int or not 1 <= port <= 65535 for port in value["listener_ports"])
                or any(
                    type(value[key]) is not int or not 0 <= value[key] <= 4096
                    for key in (
                        "socket_count",
                        "writable_file_count",
                        "unexpected_tcp_count",
                        "unexpected_socket_count",
                        "unexpected_writer_count",
                    )
                )
            ):
                raise ValueError("Invalid Linux runtime process evidence")
            if document["status"] == "verified" and (
                value["listener_ports"] != list(registered_process.listener_ports)
                or value["unexpected_tcp_count"]
                or value["unexpected_socket_count"]
                or value["unexpected_writer_count"]
            ):
                raise ValueError("Verified Linux runtime evidence contains drift")
        observed = document["observed_probes"]
        expected_probes = [[value.logical_ref, value.component_ref] for value in registration.probes]
        if (
            not isinstance(observed, list)
            or observed != sorted(observed)
            or any(not isinstance(value, list) or len(value) != 2 for value in observed)
            or any(value not in expected_probes for value in observed)
            or (document["status"] == "verified" and observed != expected_probes)
        ):
            raise ValueError("Invalid Linux runtime probe evidence")
        unsigned = {key: value for key, value in document.items() if key != "report_id"}
        digest = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        if document["report_id"] != "WRI-" + digest:
            raise ValueError("Linux runtime report identity changed")
        return json.loads(raw)
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        raise ValueError("Invalid Linux runtime inventory report") from None
