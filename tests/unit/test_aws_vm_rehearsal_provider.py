"""The separate rehearsal wheel is installable, pinned, and fail closed."""

import base64
import csv
import hashlib
import importlib
import importlib.util
import io
import json
import ssl
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZipFile

import pytest

from application.environment_execution_composition import RegisteredEnvironmentExecutionComposition

ROOT = Path(__file__).resolve().parents[2]
PROJECT = ROOT / "providers" / "aws-vm-rehearsal"


@pytest.fixture
def provider(monkeypatch):
    monkeypatch.syspath_prepend(str(PROJECT / "src"))
    module = importlib.import_module("sky_aws_vm_rehearsal.provider")
    return importlib.reload(module)


def clients(provider):
    return {
        "sts": provider._UnavailableSts(),
        "secretsmanager": provider._UnavailableSecrets(),
        "rds": provider._UnavailableRds(),
    }


def descriptor():
    return json.loads((PROJECT / "descriptor" / "sky-environment-executions-v1.json").read_text())


def test_static_descriptor_exactly_matches_composed_public_refs(provider):
    value = descriptor()
    assert value == {
        "schema_version": 1,
        "profile": "reviewed_environment_provider_executions_v1",
        "provider": provider.PROVIDER,
        "registrations": [provider.provider_pins()],
    }
    text = json.dumps(value, sort_keys=True)
    assert all(
        private not in text
        for private in (
            "password",
            "private_key",
            "known_hosts",
            "secret_arn",
            "/run/secrets",
        )
    )


def test_provider_composes_only_approved_execution_and_fixed_effect_graph(provider):
    (composition,) = provider._compose((provider.REGISTRATION_ID,), **clients(provider))
    pin = provider.provider_pins()
    assert isinstance(composition, RegisteredEnvironmentExecutionComposition)
    assert composition.execution.job.id == pin["registration_id"]
    assert composition.execution.revision == pin["execution_revision"]
    assert composition.resource_verifier_ref == pin["resource_verifier_ref"]
    assert composition.effect_ref == pin["effect_ref"]
    assert composition.resource_verifier.reference.startswith("EVR-")
    assert composition.effect.runtime_ref.startswith("ETR-")
    assert composition.effect.runtime.composer.reference.startswith("RTC-")
    runtime_document = composition.effect.runtime.registration.document()
    assert "/run/secrets" not in str(runtime_document)
    assert "arn:aws:secretsmanager" not in str(runtime_document)
    with pytest.raises(ValueError, match="Exact rehearsal"):
        provider._compose(("unapproved",), **clients(provider))


def test_rehearsal_evidence_adapters_cannot_authorize_an_effect(provider):
    runtime = provider._FailClosedRuntimeVerifier()
    probe = provider._FailClosedEntrypointProbe()
    with pytest.raises(RuntimeError, match="not activated"):
        runtime({})
    with pytest.raises(RuntimeError, match="not activated"):
        probe()
    assert runtime.reference.startswith("RVR-")
    assert probe.reference.startswith("EPR-")


def test_public_ca_is_valid_and_private_fixture_digests_are_explicit(provider):
    ssl.create_default_context(cafile=str(PROJECT / "src" / "sky_aws_vm_rehearsal" / "ca.pem"))
    assert provider.KEY_SHA256 == hashlib.sha256(b"sky-rehearsal-key-placeholder\n").hexdigest()
    assert (
        provider.KNOWN_HOSTS_SHA256
        == hashlib.sha256(b"[127.0.0.1]:2222 ssh-ed25519 AAAAREHEARSAL\n").hexdigest()
    )


def test_production_entrypoint_uses_ambient_clients_without_aws_calls(provider, monkeypatch):
    session = SimpleNamespace(client=lambda name, region_name: name + "-client")
    fake_boto3 = SimpleNamespace(Session=lambda region_name: session)
    monkeypatch.setitem(__import__("sys").modules, "boto3", fake_boto3)
    selected = (provider.REGISTRATION_ID,)
    expected = object()
    monkeypatch.setattr(
        provider,
        "_compose",
        lambda value, **kwargs: (
            expected
            if value == selected
            and kwargs
            == {
                "sts": "sts-client",
                "secretsmanager": "secretsmanager-client",
                "rds": "rds-client",
            }
            else None
        ),
    )
    assert provider.provide(selected) is expected


def test_wheel_finalizer_adds_dist_info_descriptor_and_record_hash(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "rehearsal_build_wheel", PROJECT / "tools" / "build_wheel.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source, destination = tmp_path / "source.whl", tmp_path / "final.whl"
    record_path = "sky_aws_vm_rehearsal_provider-0.1.0.dist-info/RECORD"
    module_path = "sky_aws_vm_rehearsal/provider.py"
    with ZipFile(source, "w") as wheel:
        wheel.writestr(module_path, b"provider")
        wheel.writestr(record_path, f"{module_path},,\n{record_path},,\n")
    raw = (PROJECT / "descriptor" / module.DESCRIPTOR).read_bytes()
    module.finalize(source, destination, raw)
    descriptor_path = record_path.rsplit("/", 1)[0] + "/" + module.DESCRIPTOR
    with ZipFile(destination) as wheel:
        assert wheel.read(descriptor_path) == raw
        rows = list(csv.reader(io.StringIO(wheel.read(record_path).decode())))
    recorded = next(value for value in rows if value[0] == descriptor_path)
    digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
    assert recorded == [descriptor_path, "sha256=" + digest, str(len(raw))]
