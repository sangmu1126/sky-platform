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

    def __post_init__(self):
        _ref(self.component_ref)
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

    def __post_init__(self):
        if not isinstance(self.source, RegisteredStaticSourceInventory):
            raise TypeError("Registered static source inventory required")
        if self.endpoint not in {"source", "target"}:
            raise ValueError("Registered runtime endpoint required")
        if not re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", self.boot_id):
            raise ValueError("Pinned Linux boot ID required")
        components = tuple(value[0] for value in self.source.inventory.component_roles)
        if (
            not isinstance(self.processes, tuple)
            or tuple(sorted(self.processes, key=lambda item: item.component_ref)) != self.processes
            or tuple(value.component_ref for value in self.processes) != components
            or len({value.pid for value in self.processes}) != len(self.processes)
        ):
            raise ValueError("Exactly one canonical Linux process per component required")
        if (
            not isinstance(self.probes, tuple)
            or tuple(sorted(self.probes, key=lambda item: (item.logical_ref, item.component_ref)))
            != self.probes
            or len({(value.logical_ref, value.component_ref) for value in self.probes}) != len(self.probes)
        ):
            raise ValueError("Canonical registered Linux dependency probes required")
        policies = {value.logical_ref: value for value in self.source.inventory.dependency_policies}
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
            "processes": [asdict(value) for value in self.processes],
            "probes": [asdict(value) for value in self.probes],
        }
        digest = hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        return {**value, "runtime_registration_id": "WRR-" + digest}


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


class LinuxProcWorkloadInventoryReader:
    def __init__(self, registration, proc_root, publisher, *, clock):
        if not isinstance(registration, RegisteredLinuxRuntimeInventory):
            raise TypeError("Registered Linux runtime inventory required")
        if not callable(getattr(publisher, "publish", None)) or not callable(clock):
            raise TypeError("Runtime evidence publisher and clock required")
        self.registration = registration
        self.proc_root = Path(proc_root)
        self.publisher = publisher
        self.clock = clock

    def collect(self, inventory, endpoint):
        if inventory != self.registration.inventory or endpoint != self.registration.endpoint:
            raise ValueError("Linux runtime inventory registration changed")
        try:
            report, observed = self._inspect()
            evidence_ref = self.publisher.publish(json.loads(json.dumps(report)))
            if evidence_ref != report["report_id"] or report["status"] != "verified":
                raise ValueError("Linux runtime inventory was not durably verified")
            policies = self.registration.inventory.dependency_policies
            dependencies = tuple(
                ObservedWorkloadDependency(
                    policy.logical_ref,
                    policy.category,
                    policy.component_refs,
                    policy.access_mode,
                    policy.source_location_ref if endpoint == "source" else policy.target_location_ref,
                )
                for policy in policies
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
                (evidence_ref,),
                observed,
                observed + timedelta(seconds=inventory.max_age_seconds),
            )
        except Exception:  # noqa: BLE001 -- proc diagnostics and host paths remain private
            raise WorkloadInventoryUnavailable("Registered Linux runtime inventory unavailable") from None

    def _inspect(self):
        registration = self.registration
        root = self.proc_root
        if root.is_symlink() or not root.is_dir():
            raise ValueError("Pinned proc filesystem required")
        boot_path = root / "sys/kernel/random/boot_id"
        boot_before = _read_text(boot_path, 128).strip()
        if boot_before != registration.boot_id:
            raise ValueError("Linux boot identity changed")
        probes = {(value.logical_ref, value.component_ref): value for value in registration.probes}
        matched = set()
        blockers = []
        process_reports = []
        for process in registration.processes:
            directory = root / str(process.pid)
            identity = _process_identity(directory)
            if identity != (process.start_time_ticks, process.uid, process.executable):
                raise ValueError("Registered Linux process identity changed")
            sockets, writable = _fd_inventory(directory)
            tcp = _tcp_table(directory / "net/tcp", socket.AF_INET)
            tcp6 = _tcp_table(directory / "net/tcp6", socket.AF_INET6)
            network = {inode: value for inode, value in {**tcp, **tcp6}.items() if inode in sockets}
            unknown_sockets = sockets - set(tcp) - set(tcp6)
            listeners = tuple(sorted({value[1] for value in network.values() if value[4] == "0A"}))
            if listeners != process.listener_ports:
                blockers.append("listener_registration_changed:" + process.component_ref)
            component_probes = [
                value for value in registration.probes if value.component_ref == process.component_ref
            ]
            tcp_probes = [value for value in component_probes if value.kind == "tcp"]
            file_probes = [value for value in component_probes if value.kind == "file"]
            for probe in component_probes:
                found = probe.kind == "process_memory"
                if probe.kind == "tcp":
                    found = any(
                        value[4] == "01" and value[2:4] == (probe.address, probe.port)
                        for value in network.values()
                    )
                elif probe.kind == "file":
                    found = any(_under(path, probe.path_prefix) for path in writable)
                if found:
                    matched.add((probe.logical_ref, probe.component_ref))
                else:
                    blockers.append(
                        "registered_runtime_dependency_unobserved:"
                        + probe.logical_ref
                        + ":"
                        + probe.component_ref
                    )
            unexpected_tcp = sum(
                not (
                    (value[4] == "0A" and value[1] in process.listener_ports)
                    or (value[4] == "01" and value[1] in process.listener_ports)
                    or (
                        value[4] == "01"
                        and any(value[2:4] == (probe.address, probe.port) for probe in tcp_probes)
                    )
                )
                for value in network.values()
            )
            unexpected_files = sum(
                not any(_under(path, probe.path_prefix) for probe in file_probes) for path in writable
            )
            if unexpected_tcp:
                blockers.append("unregistered_runtime_tcp:" + process.component_ref)
            if unknown_sockets:
                blockers.append("unclassified_runtime_socket:" + process.component_ref)
            if unexpected_files:
                blockers.append("unregistered_runtime_writer:" + process.component_ref)
            process_reports.append(
                {
                    "component_ref": process.component_ref,
                    "pid": process.pid,
                    "start_time_ticks": process.start_time_ticks,
                    "uid": process.uid,
                    "executable": process.executable,
                    "listener_ports": list(listeners),
                    "socket_count": len(sockets),
                    "writable_file_count": len(writable),
                    "unexpected_tcp_count": unexpected_tcp,
                    "unexpected_socket_count": len(unknown_sockets),
                    "unexpected_writer_count": unexpected_files,
                }
            )
            if _process_identity(directory) != identity:
                blockers.append("process_changed_during_runtime_analysis:" + process.component_ref)
        if matched != set(probes):
            blockers.append("runtime_probe_coverage_incomplete")
        if _read_text(boot_path, 128).strip() != boot_before:
            blockers.append("boot_changed_during_runtime_analysis")
        observed = self.clock()
        _time(observed)
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
            "execution_authorized": False,
        }
        digest = hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        return {**value, "report_id": "WRI-" + digest}, observed


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
        expected_processes = {value.component_ref: value for value in registration.processes}
        processes = document["processes"]
        if not isinstance(processes, list) or [value.get("component_ref") for value in processes] != list(
            expected_processes
        ):
            raise ValueError("Canonical Linux runtime processes required")
        process_fields = {
            "component_ref",
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
            registered_process = expected_processes[value["component_ref"]]
            if (
                set(value) != process_fields
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
