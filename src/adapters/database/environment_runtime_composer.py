"""Build one secret-free registered AWS/VM environment transfer runtime.

The registration fixes every public resource identity and transport endpoint.
Credentials are accepted only as short-lived typed materials from the runtime
secret resolver and are never included in the composition document.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import ssl
import stat
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from adapters.aws.registered_rds_inventory import RegisteredRdsInventory, RegisteredRdsInventoryVerifier
from adapters.database.environment_control import EnvironmentApplicationControl
from adapters.database.environment_fence import PostgresEnvironmentWriteFence
from adapters.database.environment_ownership import PostgresTransferOwnershipVerifier
from adapters.database.environment_traffic import EnvironmentBlueGreenTraffic
from adapters.database.environment_transfer import PostgresEnvironmentTransfer, RegisteredTransferEndpoint
from adapters.database.pinned_control_https import PinnedHTTPSControlTransport
from adapters.onprem.database_inventory import (
    PinnedVmInventoryCommand,
    VmDatabaseInventoryRegistration,
    VmDatabaseInventoryVerifier,
)
from adapters.onprem.environment_router import (
    EnvironmentNginxRouter,
    PinnedEnvironmentRouterCommand,
    RegisteredEnvironmentRouter,
)
from adapters.runtime.environment_secrets import (
    ControlRuntimeSecretMaterial,
    DatabaseRuntimeSecretMaterial,
    RouterTransportSecretMaterial,
)
from application.environment_admission import RegisteredEnvironmentExecution
from application.environment_cutover import EnvironmentDatabaseCutover
from domain.environment_transition import _digest

_ADAPTER_REF = re.compile(r"[A-Z]{3}-[a-f0-9]{64}\Z")
_CONTROLLER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_WRITER = re.compile(r"sky_transfer_[a-f0-9]{16,32}\Z")
_MARKER = re.compile(r"sky-transfer-v1:[a-f0-9]{64}\Z")
_MATERIALS = {
    "router_transport": RouterTransportSecretMaterial,
    "entrypoint_probe": ControlRuntimeSecretMaterial,
    "source_control": ControlRuntimeSecretMaterial,
    "source_database": DatabaseRuntimeSecretMaterial,
    "target_control": ControlRuntimeSecretMaterial,
    "target_database": DatabaseRuntimeSecretMaterial,
}


def _private_address(value):
    address = ipaddress.ip_address(value)
    if not address.is_private or address.is_unspecified or address.is_multicast:
        raise ValueError("Private control address required")


def _control_endpoint(value):
    url = urlsplit(value)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError("Pinned HTTPS control endpoint required")


def _pinned_ca(path, expected, label):
    _digest(expected)
    value = Path(path)
    if not value.is_absolute():
        raise ValueError(f"Registered {label} file required")
    descriptor = os.open(value, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 1 <= before.st_size <= 1024 * 1024
        ):
            raise ValueError(f"Registered {label} file required")
        content = bytearray()
        while len(content) <= 1024 * 1024:
            chunk = os.read(descriptor, min(65536, 1024 * 1024 + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        if (
            len(content) != before.st_size
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or hashlib.sha256(content).hexdigest() != expected
        ):
            raise ValueError(f"Registered {label} file changed")
        try:
            text = bytes(content).decode()
        except UnicodeError:
            raise ValueError(f"Registered {label} file required") from None
        if "-----BEGIN CERTIFICATE-----" not in text:
            raise ValueError(f"Registered {label} file required")
        return bytes(content)
    finally:
        os.close(descriptor)


def _runtime_workspace(material):
    paths = (material.private_key, material.known_hosts)
    directory = paths[0].parent
    if paths[1].parent != directory or not directory.is_absolute():
        raise ValueError("One private runtime material workspace required")
    descriptor = os.open(
        directory,
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ValueError("Private runtime material workspace required")
        for path, expected in zip(
            paths,
            (material.private_key_sha256, material.known_hosts_sha256),
            strict=True,
        ):
            source = os.open(
                path.name,
                os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                dir_fd=descriptor,
            )
            try:
                before = os.fstat(source)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_uid != os.getuid()
                    or stat.S_IMODE(before.st_mode) != 0o600
                    or not 1 <= before.st_size <= 1024 * 1024
                ):
                    raise ValueError("Private runtime transport material required")
                content = os.read(source, before.st_size + 1)
                after = os.fstat(source)
                if (
                    len(content) != before.st_size
                    or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    or hashlib.sha256(content).hexdigest() != expected
                ):
                    raise ValueError("Private runtime transport material changed")
            finally:
                os.close(source)
        return directory, descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _materialize_ca(directory, directory_descriptor, name, content):
    if not re.fullmatch(r"[a-z-]{1,32}\.pem", name):
        raise ValueError("Canonical runtime CA filename required")
    path = directory / name
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        0o400,
        dir_fd=directory_descriptor,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)
    return path


@dataclass(frozen=True)
class RegisteredEnvironmentRuntimeComposition:
    execution_revision: str
    source_endpoint: RegisteredTransferEndpoint
    target_endpoint: RegisteredTransferEndpoint
    source_rds: RegisteredRdsInventory
    target_vm: VmDatabaseInventoryRegistration
    router: RegisteredEnvironmentRouter
    router_host: str
    router_user: str
    router_port: int
    source_writer_role: str
    target_writer_role: str
    source_ownership_marker: str
    target_ownership_marker: str
    source_control_endpoint: str
    source_control_address: str
    source_controller_id: str
    target_control_endpoint: str
    target_control_address: str
    target_controller_id: str
    control_ca_path: str
    control_ca_sha256: str
    runtime_verifier_ref: str
    entrypoint_probe_ref: str
    max_rows: int = 100000
    max_bytes: int = 64 * 1024 * 1024

    def __post_init__(self):
        transfer = self.router.transfer
        if not isinstance(self.execution_revision, str) or not re.fullmatch(
            r"[a-f0-9]{64}", self.execution_revision
        ):
            raise ValueError("Exact reviewed execution revision required")
        if not all(
            isinstance(value, RegisteredTransferEndpoint)
            for value in (self.source_endpoint, self.target_endpoint)
        ):
            raise TypeError("Registered database transfer endpoints required")
        if not isinstance(self.source_rds, RegisteredRdsInventory) or not isinstance(
            self.target_vm, VmDatabaseInventoryRegistration
        ):
            raise TypeError("Registered AWS and VM database resources required")
        if not isinstance(self.router, RegisteredEnvironmentRouter):
            raise TypeError("Registered environment router required")
        if (
            self.source_endpoint.inventory.resource != transfer.source
            or self.target_endpoint.inventory.resource != transfer.target
            or self.source_rds.placement != transfer.source
            or self.target_vm.placement != transfer.target
            or self.target_vm.daemon_id != self.router.daemon_id
            or (self.source_endpoint.inventory.hostname, self.source_endpoint.inventory.port)
            != (self.source_rds.hostname, self.source_rds.port)
            or (self.target_endpoint.inventory.hostname, self.target_endpoint.inventory.port)
            != (self.target_vm.server_hostname, self.target_vm.server_port)
        ):
            raise ValueError("Composition resources differ from the registered transfer")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", self.router_host) or not re.fullmatch(
            r"[a-z_][a-z0-9_-]{0,31}", self.router_user
        ):
            raise ValueError("Pinned router SSH identity required")
        if type(self.router_port) is not int or not 1 <= self.router_port <= 65535:
            raise ValueError("Pinned router SSH port required")
        if not all(_WRITER.fullmatch(value) for value in (self.source_writer_role, self.target_writer_role)):
            raise ValueError("Restricted transfer writer roles required")
        if not all(
            _MARKER.fullmatch(value) for value in (self.source_ownership_marker, self.target_ownership_marker)
        ):
            raise ValueError("Pinned database ownership markers required")
        for endpoint, address, controller in (
            (self.source_control_endpoint, self.source_control_address, self.source_controller_id),
            (self.target_control_endpoint, self.target_control_address, self.target_controller_id),
        ):
            _control_endpoint(endpoint)
            _private_address(address)
            if not isinstance(controller, str) or not _CONTROLLER.fullmatch(controller):
                raise ValueError("Pinned application controller identity required")
        if self.source_controller_id == self.target_controller_id:
            raise ValueError("Distinct application controller identities required")
        _pinned_ca(self.control_ca_path, self.control_ca_sha256, "control CA")
        if not all(
            isinstance(value, str) and _ADAPTER_REF.fullmatch(value)
            for value in (self.runtime_verifier_ref, self.entrypoint_probe_ref)
        ):
            raise ValueError("Attested runtime verifier and entrypoint probe references required")
        if type(self.max_rows) is not int or not 1 <= self.max_rows <= 100000:
            raise ValueError("Bounded transfer row limit required")
        if type(self.max_bytes) is not int or not 1 <= self.max_bytes <= 64 * 1024 * 1024:
            raise ValueError("Bounded transfer byte limit required")

    def document(self):
        def endpoint(value):
            inventory = value.inventory
            return {
                "inventory": {
                    "resource": asdict(inventory.resource),
                    "hostname": inventory.hostname,
                    "port": inventory.port,
                    "login_role": inventory.login_role,
                    "ca_sha256": inventory.ca_sha256,
                },
                "connect_port": value.connect_port,
                "connect_hostaddr": value.connect_hostaddr,
            }

        value = {
            "schema_version": 1,
            "profile": "registered_aws_vm_environment_runtime_composition_v1",
            "execution_revision": self.execution_revision,
            "source_endpoint": endpoint(self.source_endpoint),
            "target_endpoint": endpoint(self.target_endpoint),
            "source_rds": asdict(self.source_rds),
            "target_vm": asdict(self.target_vm),
            "router": asdict(self.router),
            "router_host": self.router_host,
            "router_user": self.router_user,
            "router_port": self.router_port,
            "source_writer_role": self.source_writer_role,
            "target_writer_role": self.target_writer_role,
            "source_ownership_marker": self.source_ownership_marker,
            "target_ownership_marker": self.target_ownership_marker,
            "source_control_endpoint": self.source_control_endpoint,
            "source_control_address": self.source_control_address,
            "source_controller_id": self.source_controller_id,
            "target_control_endpoint": self.target_control_endpoint,
            "target_control_address": self.target_control_address,
            "target_controller_id": self.target_controller_id,
            "control_ca_sha256": self.control_ca_sha256,
            "runtime_verifier_ref": self.runtime_verifier_ref,
            "entrypoint_probe_ref": self.entrypoint_probe_ref,
            "max_rows": self.max_rows,
            "max_bytes": self.max_bytes,
        }
        digest = hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        return {**value, "composition_ref": "RTC-" + digest}


class RegisteredAwsVmEnvironmentRuntimeComposer:
    """Compose exact runtime objects while resolver materials remain open."""

    def __init__(
        self,
        execution,
        registration,
        *,
        sts,
        rds,
        runtime_verifier,
        entrypoint_probe,
        clock=lambda: datetime.now(UTC),
    ):
        if not isinstance(execution, RegisteredEnvironmentExecution):
            raise TypeError("Registered environment execution required")
        if (
            not isinstance(registration, RegisteredEnvironmentRuntimeComposition)
            or registration.execution_revision != execution.revision
            or registration.router.transfer != execution.job.transfer
        ):
            raise ValueError("Runtime composition differs from reviewed execution")
        if not callable(getattr(sts, "get_caller_identity", None)) or not callable(
            getattr(rds, "describe_db_instances", None)
        ):
            raise TypeError("Read-only AWS database clients required")
        if (
            not callable(runtime_verifier) and not callable(getattr(runtime_verifier, "bind", None))
        ) or getattr(runtime_verifier, "reference", None) != registration.runtime_verifier_ref:
            raise ValueError("Attested runtime verifier required")
        if (
            not callable(entrypoint_probe) and not callable(getattr(entrypoint_probe, "bind", None))
        ) or getattr(entrypoint_probe, "reference", None) != registration.entrypoint_probe_ref:
            raise ValueError("Attested entrypoint probe required")
        if not callable(clock):
            raise TypeError("Runtime evidence clock required")
        self.execution, self.registration = execution, registration
        self.sts, self.rds = sts, rds
        self.runtime_verifier, self.entrypoint_probe = runtime_verifier, entrypoint_probe
        self.clock = clock
        self.reference = registration.document()["composition_ref"]

    @staticmethod
    def _connect(endpoint, material):
        def connect():
            import psycopg

            inventory = endpoint.inventory
            values = {
                "host": inventory.hostname,
                "port": endpoint.connect_port,
                "dbname": inventory.resource.database_name,
                "user": material.username,
                "password": material.password,
                "sslmode": "verify-full",
                "sslrootcert": inventory.sslrootcert,
                "connect_timeout": 5,
            }
            if endpoint.connect_hostaddr is not None:
                values["hostaddr"] = endpoint.connect_hostaddr
            return psycopg.connect(**values)

        return connect

    def __call__(self, execution, materials, *, guard, journal):
        if execution != self.execution or not callable(guard) or not callable(journal):
            raise ValueError("Exact guarded environment runtime execution required")
        if (
            not isinstance(materials, dict)
            or set(materials) != set(_MATERIALS)
            or any(not isinstance(materials[name], kind) for name, kind in _MATERIALS.items())
        ):
            raise TypeError("Complete typed environment runtime materials required")
        r = self.registration
        source_secret, target_secret = materials["source_database"], materials["target_database"]
        if (
            source_secret.username != r.source_endpoint.inventory.login_role
            or target_secret.username != r.target_endpoint.inventory.login_role
        ):
            raise ValueError("Database secret roles differ from registered endpoints")
        router_material = materials["router_transport"]
        workspace, workspace_descriptor = _runtime_workspace(router_material)
        try:
            control_ca = _pinned_ca(r.control_ca_path, r.control_ca_sha256, "control CA")
            source_ca = _pinned_ca(
                r.source_endpoint.inventory.sslrootcert,
                r.source_endpoint.inventory.ca_sha256,
                "database CA",
            )
            target_ca = _pinned_ca(
                r.target_endpoint.inventory.sslrootcert,
                r.target_endpoint.inventory.ca_sha256,
                "database CA",
            )
            source_endpoint = replace(
                r.source_endpoint,
                inventory=replace(
                    r.source_endpoint.inventory,
                    sslrootcert=str(
                        _materialize_ca(
                            workspace,
                            workspace_descriptor,
                            "source-ca.pem",
                            source_ca,
                        )
                    ),
                ),
            )
            target_endpoint = replace(
                r.target_endpoint,
                inventory=replace(
                    r.target_endpoint.inventory,
                    sslrootcert=str(
                        _materialize_ca(
                            workspace,
                            workspace_descriptor,
                            "target-ca.pem",
                            target_ca,
                        )
                    ),
                ),
            )
        finally:
            os.close(workspace_descriptor)
        ssh = PinnedVmInventoryCommand(
            host=r.router_host,
            user=r.router_user,
            port=r.router_port,
            private_key=router_material.private_key,
            known_hosts=router_material.known_hosts,
        )
        runtime_verifier = self.runtime_verifier
        if callable(getattr(runtime_verifier, "bind", None)):
            runtime_verifier = runtime_verifier.bind(ssh)
            if (
                not callable(runtime_verifier)
                or getattr(runtime_verifier, "reference", None) != r.runtime_verifier_ref
            ):
                raise ValueError("Bound runtime verifier differs from registration")
        entrypoint_probe = self.entrypoint_probe
        if callable(getattr(entrypoint_probe, "bind", None)):
            entrypoint_probe = entrypoint_probe.bind(materials["entrypoint_probe"], guard=guard)
            if (
                not callable(entrypoint_probe)
                or getattr(entrypoint_probe, "reference", None) != r.entrypoint_probe_ref
            ):
                raise ValueError("Bound entrypoint probe differs from registration")
        source_connect = self._connect(source_endpoint, source_secret)
        target_connect = self._connect(target_endpoint, target_secret)
        source_provider = RegisteredRdsInventoryVerifier(
            r.source_rds, sts=self.sts, rds=self.rds, clock=self.clock
        )
        target_provider = VmDatabaseInventoryVerifier(r.target_vm, ssh, clock=self.clock)
        source_verifier = PostgresTransferOwnershipVerifier(
            source_endpoint,
            source_provider,
            source_connect,
            writer_role=r.source_writer_role,
            marker=r.source_ownership_marker,
            clock=self.clock,
        )
        target_verifier = PostgresTransferOwnershipVerifier(
            target_endpoint,
            target_provider,
            target_connect,
            writer_role=r.target_writer_role,
            marker=r.target_ownership_marker,
            clock=self.clock,
        )
        transfer = execution.job.transfer
        transport = PostgresEnvironmentTransfer(
            transfer,
            source_endpoint,
            target_endpoint,
            source_connect,
            target_connect,
            source_verifier,
            target_verifier,
            clock=self.clock,
            max_rows=r.max_rows,
            max_bytes=r.max_bytes,
        )
        source_fence = PostgresEnvironmentWriteFence(
            transport, "source", r.source_writer_role, r.source_ownership_marker
        )
        target_fence = PostgresEnvironmentWriteFence(
            transport, "target", r.target_writer_role, r.target_ownership_marker
        )

        def verify_runtime(binding):
            guard()
            result = runtime_verifier(binding)
            guard()
            return result is True

        def probe_entrypoint():
            guard()
            result = entrypoint_probe()
            guard()
            return result

        context = ssl.create_default_context(cadata=control_ca.decode())
        controllers = []
        for side, endpoint, address, controller_id in (
            (
                "source",
                r.source_control_endpoint,
                r.source_control_address,
                r.source_controller_id,
            ),
            (
                "target",
                r.target_control_endpoint,
                r.target_control_address,
                r.target_controller_id,
            ),
        ):
            binding = asdict(transfer.source if side == "source" else transfer.target)

            def control_guard(binding=binding):
                if verify_runtime(binding) is not True:
                    raise RuntimeError("Registered control runtime ownership changed")

            secret = materials[side + "_control"]
            control_transport = PinnedHTTPSControlTransport(
                endpoint,
                secret.token,
                address=address,
                ssl_context=context,
                guard=control_guard,
                response_timeout=60,
            )
            controllers.append(
                EnvironmentApplicationControl(
                    transfer,
                    endpoint,
                    secret.token,
                    controller_id=controller_id,
                    guard=control_guard,
                    transport=control_transport,
                    ssl_context=context,
                )
            )
        router = EnvironmentNginxRouter(
            r.router,
            PinnedEnvironmentRouterCommand(ssh, r.router),
            guard=guard,
            verify_runtime=verify_runtime,
            probe_entrypoint=probe_entrypoint,
        )
        traffic = EnvironmentBlueGreenTraffic(transfer, controllers[0], controllers[1], router, guard=guard)
        flow = EnvironmentDatabaseCutover(
            transfer,
            transport,
            source_fence,
            target_fence,
            traffic,
            guard=guard,
            journal=journal,
        )
        return transport, flow
