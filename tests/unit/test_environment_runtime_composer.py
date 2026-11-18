"""The AWS/VM composer binds public registrations and short-lived materials."""

import hashlib
import os
import ssl
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from adapters.aws.registered_rds_inventory import RegisteredRdsInventory
from adapters.database.environment_control import EnvironmentApplicationControl
from adapters.database.environment_runtime_composer import (
    RegisteredAwsVmEnvironmentRuntimeComposer,
    RegisteredEnvironmentRuntimeComposition,
    _materialize_ca,
    _runtime_workspace,
)
from adapters.database.environment_transfer import RegisteredTransferEndpoint
from adapters.database.migration_inventory import PostgresInventoryRegistration
from adapters.onprem.database_inventory import VmDatabaseInventoryRegistration
from adapters.onprem.environment_router import RegisteredEnvironmentRouter
from adapters.runtime.environment_secrets import (
    ControlRuntimeSecretMaterial,
    DatabaseRuntimeSecretMaterial,
    RouterTransportSecretMaterial,
)
from application.environment_cutover import EnvironmentDatabaseCutover
from tests.unit.test_database_transfer import NOW
from tests.unit.test_environment_admission import registered


class Adapter:
    def __init__(self, reference, result):
        self.reference, self.result = reference, result
        self.calls = []

    def __call__(self, *args):
        self.calls.append(args)
        return self.result(*args) if callable(self.result) else self.result


def fixture(tmp_path):
    tmp_path.chmod(0o700)
    execution = registered()
    transfer = execution.job.transfer
    ca = tmp_path / "ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\nregistered-public-ca\n-----END CERTIFICATE-----\n")
    digest = hashlib.sha256(ca.read_bytes()).hexdigest()
    source_role, target_role = "sky_transfer_" + "a" * 16, "sky_transfer_" + "b" * 16
    source_endpoint = RegisteredTransferEndpoint(
        PostgresInventoryRegistration(transfer.source, "source.rds.test", 5432, source_role, str(ca), digest),
        35432,
        "127.0.0.1",
    )
    target_endpoint = RegisteredTransferEndpoint(
        PostgresInventoryRegistration(transfer.target, "target.vm.test", 5432, target_role, str(ca), digest),
        45432,
        "127.0.0.1",
    )
    source_rds = RegisteredRdsInventory(
        transfer.source,
        "db-immutable",
        "source.rds.test",
        5432,
        "vpc-12345678",
        ("sg-12345678",),
        (("sky-managed", "true"),),
    )
    target_vm = VmDatabaseInventoryRegistration(
        transfer.target,
        "daemon-123456789",
        "c" * 64,
        "sha256:" + "d" * 64,
        "owned-database",
        "target.vm.test",
        5432,
    )
    router = RegisteredEnvironmentRouter(
        transfer,
        "daemon-123456789",
        "e" * 64,
        "sha256:" + "f" * 64,
        "10.0.0.10",
        8443,
        "source.app.test",
        "172.16.0.10",
        8443,
        "target.app.test",
        "owned-network",
        "owned-router-config",
    )
    registration = RegisteredEnvironmentRuntimeComposition(
        execution.revision,
        source_endpoint,
        target_endpoint,
        source_rds,
        target_vm,
        router,
        "127.0.0.1",
        "operator",
        2222,
        source_role,
        target_role,
        "sky-transfer-v1:" + "1" * 64,
        "sky-transfer-v1:" + "2" * 64,
        "https://source.app.test:38443/control",
        "127.0.0.1",
        "source-controller",
        "https://target.app.test:48443/control",
        "127.0.0.1",
        "target-controller",
        str(ca),
        digest,
        "RVR-" + "3" * 64,
        "EPR-" + "4" * 64,
    )
    runtime_verifier = Adapter(registration.runtime_verifier_ref, True)
    entrypoint_probe = Adapter(registration.entrypoint_probe_ref, {"binding_hash": "unused"})
    sts = Mock(get_caller_identity=Mock(return_value={"Account": "111111111111"}))
    rds = Mock(meta=SimpleNamespace(region_name="ap-northeast-2"))
    composer = RegisteredAwsVmEnvironmentRuntimeComposer(
        execution,
        registration,
        sts=sts,
        rds=rds,
        runtime_verifier=runtime_verifier,
        entrypoint_probe=entrypoint_probe,
        clock=lambda: NOW,
    )
    key, hosts = tmp_path / "key", tmp_path / "known_hosts"
    key.write_text("private-key")
    hosts.write_text(
        "[127.0.0.1]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g\n"
    )
    key.chmod(0o600)
    hosts.chmod(0o600)
    materials = {
        "router_transport": RouterTransportSecretMaterial(
            key,
            hosts,
            hashlib.sha256(key.read_bytes()).hexdigest(),
            hashlib.sha256(hosts.read_bytes()).hexdigest(),
        ),
        "entrypoint_probe": ControlRuntimeSecretMaterial("entrypoint-private-token"),
        "source_control": ControlRuntimeSecretMaterial("source-private-token"),
        "source_database": DatabaseRuntimeSecretMaterial(source_role, "source-private-password"),
        "target_control": ControlRuntimeSecretMaterial("target-private-token"),
        "target_database": DatabaseRuntimeSecretMaterial(target_role, "target-private-password"),
    }
    return execution, registration, composer, materials


def tls_context():
    return SimpleNamespace(verify_mode=ssl.CERT_REQUIRED, check_hostname=True)


def test_composition_document_is_secret_free_and_binds_every_public_registration(tmp_path):
    _execution, registration, composer, materials = fixture(tmp_path)
    document = registration.document()
    assert composer.reference == document["composition_ref"]
    assert composer.reference.startswith("RTC-")
    text = str(document)
    assert "private-password" not in text and "private-token" not in text
    assert all(str(value.private_key) not in text for value in [materials["router_transport"]])
    assert str(tmp_path) not in text and "sslrootcert" not in text

    moved = tmp_path / "moved-ca.pem"
    moved.write_bytes((tmp_path / "ca.pem").read_bytes())
    moved_registration = replace(
        registration,
        source_endpoint=replace(
            registration.source_endpoint,
            inventory=replace(registration.source_endpoint.inventory, sslrootcert=str(moved)),
        ),
        target_endpoint=replace(
            registration.target_endpoint,
            inventory=replace(registration.target_endpoint.inventory, sslrootcert=str(moved)),
        ),
        control_ca_path=str(moved),
    )
    assert moved_registration.document()["composition_ref"] == document["composition_ref"]


def test_composer_builds_one_guarded_transport_and_cutover_graph(tmp_path):
    execution, _registration, composer, materials = fixture(tmp_path)
    guard, journal = Mock(), Mock()
    with patch(
        "adapters.database.environment_runtime_composer.ssl.create_default_context",
        return_value=tls_context(),
    ) as create_context:
        transport, flow = composer(execution, materials, guard=guard, journal=journal)
    create_context.assert_called_once_with(cadata=(tmp_path / "ca.pem").read_text())
    assert isinstance(flow, EnvironmentDatabaseCutover)
    assert flow.transfer == transport.transfer == execution.job.transfer
    assert flow._external_guard is guard and flow.journal is journal
    assert flow.source.transport is flow.target.transport is transport
    assert len(flow.traffic.controllers) == 2
    assert all(isinstance(value, EnvironmentApplicationControl) for value in flow.traffic.controllers)
    assert flow.traffic.router.guard is guard
    assert transport.verifiers[0].provider_verifier.registration == composer.registration.source_rds
    assert transport.verifiers[1].provider_verifier.registration == composer.registration.target_vm


def test_database_connectors_use_registered_tls_names_tunnels_and_resolved_roles(tmp_path):
    execution, registration, composer, materials = fixture(tmp_path)
    with patch(
        "adapters.database.environment_runtime_composer.ssl.create_default_context",
        return_value=tls_context(),
    ):
        transport, _flow = composer(execution, materials, guard=Mock(), journal=Mock())
    Path(registration.source_endpoint.inventory.sslrootcert).write_text("changed-after-composition")
    with patch("psycopg.connect", side_effect=["source-db", "target-db"]) as connect:
        assert transport.source_connect() == "source-db"
        assert transport.target_connect() == "target-db"
    source, target = (value.kwargs for value in connect.call_args_list)
    assert (source["host"], source["hostaddr"], source["port"]) == (
        "source.rds.test",
        "127.0.0.1",
        35432,
    )
    assert (target["host"], target["hostaddr"], target["port"]) == (
        "target.vm.test",
        "127.0.0.1",
        45432,
    )
    assert source["sslmode"] == target["sslmode"] == "verify-full"
    assert source["sslrootcert"] != composer.registration.source_endpoint.inventory.sslrootcert
    assert target["sslrootcert"] != composer.registration.target_endpoint.inventory.sslrootcert
    assert Path(source["sslrootcert"]).parent == materials["router_transport"].private_key.parent
    assert Path(target["sslrootcert"]).parent == materials["router_transport"].private_key.parent
    assert Path(source["sslrootcert"]).stat().st_mode & 0o777 == 0o400
    assert Path(target["sslrootcert"]).stat().st_mode & 0o777 == 0o400
    assert hashlib.sha256(Path(source["sslrootcert"]).read_bytes()).hexdigest() == (
        registration.source_endpoint.inventory.ca_sha256
    )
    assert hashlib.sha256(Path(target["sslrootcert"]).read_bytes()).hexdigest() == (
        registration.target_endpoint.inventory.ca_sha256
    )
    assert source["password"] == "source-private-password"
    assert target["password"] == "target-private-password"


def test_composer_binds_runtime_evidence_factory_to_short_lived_router_transport(tmp_path):
    execution, registration, composer, materials = fixture(tmp_path)

    class Bound:
        reference = registration.runtime_verifier_ref

        def __call__(self, _binding):
            return True

    class Factory:
        reference = registration.runtime_verifier_ref

        def __init__(self):
            self.ssh = None

        def bind(self, ssh):
            self.ssh = ssh
            return Bound()

    factory = Factory()
    composer = RegisteredAwsVmEnvironmentRuntimeComposer(
        execution,
        registration,
        sts=composer.sts,
        rds=composer.rds,
        runtime_verifier=factory,
        entrypoint_probe=composer.entrypoint_probe,
        clock=composer.clock,
    )
    with patch(
        "adapters.database.environment_runtime_composer.ssl.create_default_context",
        return_value=tls_context(),
    ):
        _transport, flow = composer(execution, materials, guard=Mock(), journal=Mock())
    assert factory.ssh is not None
    assert factory.ssh.arguments[factory.ssh.arguments.index("-i") + 1] == str(
        materials["router_transport"].private_key
    )
    assert flow.traffic.router.verify_runtime(flow.traffic.router.bindings[0]) is True


def test_runtime_ca_materialization_uses_private_directory_fd_and_exact_mode(tmp_path):
    workspace = tmp_path / "runtime"
    workspace.mkdir(mode=0o700)
    descriptor = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY)
    previous = os.umask(0o777)
    try:
        path = _materialize_ca(workspace, descriptor, "source-ca.pem", b"registered-ca")
    finally:
        os.umask(previous)
        os.close(descriptor)
    assert path.read_bytes() == b"registered-ca"
    assert path.stat().st_mode & 0o777 == 0o400


def test_runtime_workspace_detects_transport_mode_change_during_read(tmp_path):
    _execution, _registration, _composer, materials = fixture(tmp_path)
    original = os.read
    changed = False

    def mutate_mode(descriptor, size):
        nonlocal changed
        content = original(descriptor, size)
        if not changed:
            os.fchmod(descriptor, 0o400)
            changed = True
        return content

    with (
        patch("adapters.database.environment_runtime_composer.os.read", side_effect=mutate_mode),
        pytest.raises(ValueError, match="transport material changed"),
    ):
        _runtime_workspace(materials["router_transport"])


def test_composer_binds_entrypoint_factory_to_its_separate_short_lived_token(tmp_path):
    execution, registration, composer, materials = fixture(tmp_path)

    class Bound:
        reference = registration.entrypoint_probe_ref

        def __call__(self):
            return {"binding_hash": "a" * 64}

    class Factory:
        reference = registration.entrypoint_probe_ref

        def __init__(self):
            self.material, self.guard = None, None

        def bind(self, material, *, guard):
            self.material, self.guard = material, guard
            return Bound()

    factory = Factory()
    guard = Mock()
    composer = RegisteredAwsVmEnvironmentRuntimeComposer(
        execution,
        registration,
        sts=composer.sts,
        rds=composer.rds,
        runtime_verifier=composer.runtime_verifier,
        entrypoint_probe=factory,
        clock=composer.clock,
    )
    with patch(
        "adapters.database.environment_runtime_composer.ssl.create_default_context",
        return_value=tls_context(),
    ):
        _transport, flow = composer(execution, materials, guard=guard, journal=Mock())
    assert factory.material is materials["entrypoint_probe"]
    assert factory.guard is guard
    assert flow.traffic.router.probe_entrypoint() == {"binding_hash": "a" * 64}


@pytest.mark.parametrize(
    "change",
    ["execution", "resource", "adapter", "secret-role", "ca", "ca-mode", "workspace", "router-hash"],
)
def test_changed_registration_adapter_secret_or_ca_fails_closed(tmp_path, change):
    execution, registration, composer, materials = fixture(tmp_path)
    if change == "execution":
        registration = replace(registration, execution_revision="0" * 64)
        with pytest.raises(ValueError, match="reviewed execution"):
            RegisteredAwsVmEnvironmentRuntimeComposer(
                execution,
                registration,
                sts=composer.sts,
                rds=composer.rds,
                runtime_verifier=composer.runtime_verifier,
                entrypoint_probe=composer.entrypoint_probe,
            )
        return
    if change == "resource":
        with pytest.raises(ValueError, match="resources differ"):
            replace(
                registration,
                target_vm=replace(registration.target_vm, server_hostname="other.vm.test"),
            )
        return
    if change == "adapter":
        with pytest.raises(ValueError, match="runtime verifier"):
            RegisteredAwsVmEnvironmentRuntimeComposer(
                execution,
                registration,
                sts=composer.sts,
                rds=composer.rds,
                runtime_verifier=Adapter("RVR-" + "9" * 64, True),
                entrypoint_probe=composer.entrypoint_probe,
            )
        return
    if change == "secret-role":
        materials["source_database"] = DatabaseRuntimeSecretMaterial("sky_transfer_" + "9" * 16, "private")
        with (
            patch(
                "adapters.database.environment_runtime_composer.ssl.create_default_context",
                return_value=tls_context(),
            ),
            pytest.raises(ValueError, match="secret roles"),
        ):
            composer(execution, materials, guard=Mock(), journal=Mock())
        return
    if change == "ca":
        with open(registration.control_ca_path, "a") as value:
            value.write("changed")
        message = "control CA"
    elif change == "ca-mode":
        Path(registration.control_ca_path).chmod(0o666)
        message = "control CA"
    elif change == "workspace":
        tmp_path.chmod(0o755)
        message = "runtime material workspace"
    else:
        materials["router_transport"] = replace(materials["router_transport"], private_key_sha256="0" * 64)
        message = "transport material changed"
    with pytest.raises(ValueError, match=message):
        composer(execution, materials, guard=Mock(), journal=Mock())
