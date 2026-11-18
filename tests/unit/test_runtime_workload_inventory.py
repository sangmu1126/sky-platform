"""Registered Linux process inventory is read-only, bounded and fail-closed."""

import json
from dataclasses import replace

import pytest

from adapters.runtime.workload_inventory import (
    LinuxProcWorkloadInventoryReader,
    RegisteredLinuxDependencyProbe,
    RegisteredLinuxProcess,
    RegisteredLinuxRuntimeInventory,
)
from adapters.source.workload_inventory import RegisteredStaticSourceInventory
from application.deployment_core import source_digest
from domain.workload_inventory import RegisteredDependencyPolicy, RegisteredWorkloadInventory
from ports.workload_inventory import WorkloadInventoryUnavailable
from tests.unit.test_environment_transition import NOW
from tests.unit.test_workload_inventory import registration

BOOT_ID = "11111111-2222-3333-4444-555555555555"
TCP_HEADER = "  sl  local_address rem_address   st tx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def runtime_source(project):
    (project / "api.py").write_text("import websockets\n")
    (project / "worker.py").write_text("open('/data/output.db', 'a')\n")
    (project / "requirements.txt").write_text("websockets>=12\n")
    base = registration()
    policies = (
        RegisteredDependencyPolicy(
            "local-file",
            "filesystem",
            ("jobs",),
            "write",
            "aws-file",
            "vm-file",
            "migrate",
        ),
        RegisteredDependencyPolicy(
            "session",
            "session_state",
            ("api",),
            "read_write",
            "aws-memory",
            "vm-memory",
            "drain_reconnect",
        ),
    )
    inventory = RegisteredWorkloadInventory(
        "runtime-dependencies-v1",
        replace(base.scope, source_revision=source_digest(project)),
        base.component_roles,
        policies,
    )
    return RegisteredStaticSourceInventory(
        inventory,
        "python",
        (("api", ("api.py",)), ("jobs", ("worker.py",))),
    )


def process(proc, pid, name, start, executable, *, sockets=(), files=()):
    root = proc / str(pid)
    (root / "fd").mkdir(parents=True)
    (root / "fdinfo").mkdir()
    (root / "net").mkdir()
    fields = ["S", *(["0"] * 18), str(start)]
    (root / "stat").write_text(f"{pid} ({name}) " + " ".join(fields) + "\n")
    (root / "status").write_text("Uid:\t1000\t1000\t1000\t1000\n")
    (root / "exe").symlink_to(executable)
    tcp = [TCP_HEADER]
    for fd, inode, local_hex, local_port, remote_hex, remote_port, state in sockets:
        (root / "fd" / str(fd)).symlink_to(f"socket:[{inode}]")
        tcp.append(
            f" {fd}: {local_hex}:{local_port:04X} {remote_hex}:{remote_port:04X} {state} "
            f"00000000:00000000 00:00000000 00000000 1000 0 {inode}\n"
        )
    for fd, target, flags in files:
        (root / "fd" / str(fd)).symlink_to(target)
        (root / "fdinfo" / str(fd)).write_text(f"pos:\t0\nflags:\t{flags:o}\n")
    (root / "net/tcp").write_text("".join(tcp))
    (root / "net/tcp6").write_text(TCP_HEADER)


def runtime_case(tmp_path, *, endpoint="source", extra_file=False, writer=True):
    project = tmp_path / "project"
    project.mkdir()
    source = runtime_source(project)
    proc = tmp_path / "proc"
    (proc / "sys/kernel/random").mkdir(parents=True)
    (proc / "sys/kernel/random/boot_id").write_text(BOOT_ID + "\n")
    api_sockets = (
        (3, 100, "00000000", 8080, "00000000", 0, "0A"),
        (4, 101, "0100007F", 8080, "0100007F", 50000, "01"),
    )
    process(proc, 101, "api", 111, "/usr/bin/python3", sockets=api_sockets)
    files = []
    if writer:
        files.append((3, "/data/output.db", 0o100002))
    if extra_file:
        files.append((4, "/private/leak.txt", 0o100001))
    process(proc, 202, "jobs", 222, "/usr/bin/python3", files=files)
    registered = RegisteredLinuxRuntimeInventory(
        source,
        endpoint,
        BOOT_ID,
        (
            RegisteredLinuxProcess("api", 101, 111, 1000, "/usr/bin/python3", (8080,)),
            RegisteredLinuxProcess("jobs", 202, 222, 1000, "/usr/bin/python3"),
        ),
        (
            RegisteredLinuxDependencyProbe("local-file", "jobs", "file", path_prefix="/data"),
            RegisteredLinuxDependencyProbe("session", "api", "process_memory"),
        ),
    )
    published = {}

    class Publisher:
        def publish(self, report):
            published[report["report_id"]] = report
            return report["report_id"]

    reader = LinuxProcWorkloadInventoryReader(
        registered,
        proc,
        Publisher(),
        clock=lambda: NOW,
    )
    return reader, source, proc, published


def test_proc_reader_verifies_process_listener_writer_and_ignores_inbound_client(tmp_path):
    reader, source, _proc, published = runtime_case(tmp_path)
    snapshot = reader.collect(source.inventory, "source")
    assert snapshot.evidence_refs[0].startswith("WRI-")
    assert dict(snapshot.coverage)["filesystem"] == "present"
    assert dict(snapshot.coverage)["session_state"] == "present"
    assert dict(snapshot.coverage)["database"] == "verified_absent"
    report = published[snapshot.evidence_refs[0]]
    assert report["status"] == "verified"
    api = report["processes"][0]
    assert api["listener_ports"] == [8080] and api["unexpected_tcp_count"] == 0
    assert report["observed_probes"] == [["local-file", "jobs"], ["session", "api"]]


@pytest.mark.parametrize("change", ["missing_writer", "unexpected_writer", "unknown_socket", "listener"])
def test_missing_or_unregistered_runtime_state_is_persisted_blocked(change, tmp_path):
    reader, source, proc, published = runtime_case(
        tmp_path,
        writer=change != "missing_writer",
        extra_file=change == "unexpected_writer",
    )
    if change == "listener":
        reader.registration = replace(
            reader.registration,
            processes=(
                replace(reader.registration.processes[0], listener_ports=(9090,)),
                reader.registration.processes[1],
            ),
        )
    elif change == "unknown_socket":
        (proc / "202/fd/9").symlink_to("socket:[999]")
    with pytest.raises(WorkloadInventoryUnavailable):
        reader.collect(source.inventory, "source")
    assert len(published) == 1
    report = next(iter(published.values()))
    assert report["status"] == "blocked" and report["blockers"]
    assert "/private/leak.txt" not in json.dumps(report)


def test_process_reuse_and_endpoint_drift_never_publish_runtime_evidence(tmp_path):
    reader, source, proc, published = runtime_case(tmp_path)
    stat = proc / "101/stat"
    stat.write_text(stat.read_text().replace(" 111\n", " 999\n"))
    with pytest.raises(WorkloadInventoryUnavailable):
        reader.collect(source.inventory, "source")
    assert not published
    with pytest.raises(ValueError):
        reader.collect(source.inventory, "target")


def test_runtime_registration_requires_every_policy_component_probe(tmp_path):
    reader, _source, _proc, _published = runtime_case(tmp_path)
    with pytest.raises(ValueError, match="Every registered dependency"):
        replace(reader.registration, probes=reader.registration.probes[:-1])
