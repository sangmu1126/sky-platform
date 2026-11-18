"""The separate rehearsal wheel is installable, pinned, and fail closed."""

import base64
import csv
import hashlib
import importlib
import importlib.util
import io
import json
import ssl
import sys
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

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
        == hashlib.sha256(
            b"[127.0.0.1]:2222 ssh-ed25519 "
            b"AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g\n"
        ).hexdigest()
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


def test_wheel_finalizer_adds_descriptor_and_is_reproducible(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "rehearsal_build_wheel", PROJECT / "tools" / "build_wheel.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sources = (tmp_path / "source-one.whl", tmp_path / "source-two.whl")
    destinations = (tmp_path / "final-one.whl", tmp_path / "final-two.whl")
    record_path = "sky_aws_vm_rehearsal_provider-0.1.0.dist-info/RECORD"
    module_path = "sky_aws_vm_rehearsal/provider.py"
    for index, source in enumerate(sources, start=1):
        with ZipFile(source, "w") as wheel:
            provider_source = b"provider"
            provider_digest = (
                base64.urlsafe_b64encode(hashlib.sha256(provider_source).digest()).rstrip(b"=").decode()
            )
            record = (
                f"{module_path},sha256={provider_digest},{len(provider_source)}\n{record_path},,\n"
            ).encode()
            for name, value in ((module_path, provider_source), (record_path, record)):
                info = ZipInfo(name, date_time=(2026, index, index, index, index, index * 2))
                info.compress_type = ZIP_DEFLATED
                info.external_attr = (0o100600 + index) << 16
                wheel.writestr(info, value)
    raw = (PROJECT / "descriptor" / module.DESCRIPTOR).read_bytes()
    for source, destination in zip(sources, destinations, strict=True):
        module.finalize(source, destination, raw)
    assert destinations[0].read_bytes() == destinations[1].read_bytes()
    descriptor_path = record_path.rsplit("/", 1)[0] + "/" + module.DESCRIPTOR
    with ZipFile(destinations[0]) as wheel:
        assert wheel.read(descriptor_path) == raw
        assert all(value.date_time == (1980, 1, 1, 0, 0, 0) for value in wheel.infolist())
        assert all(value.external_attr >> 16 == 0o100644 for value in wheel.infolist())
        assert wheel.namelist() == sorted(wheel.namelist())
        rows = list(csv.reader(io.StringIO(wheel.read(record_path).decode())))
    recorded = next(value for value in rows if value[0] == descriptor_path)
    digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
    assert recorded == [descriptor_path, "sha256=" + digest, str(len(raw))]


@pytest.mark.parametrize("name", ["/absolute", "../escape", "a//b", "a\\b", "directory/", "a\x00b"])
def test_wheel_finalizer_rejects_noncanonical_paths(name):
    spec = importlib.util.spec_from_file_location(
        "rehearsal_build_wheel_paths", PROJECT / "tools" / "build_wheel.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with pytest.raises(ValueError, match="Canonical provider wheel path"):
        module._canonical_info(name)


def test_provider_build_uses_offline_isolated_pip_and_minimal_environment(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "rehearsal_build_wheel_isolation", PROJECT / "tools" / "build_wheel.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    project = tmp_path / "project"
    project.mkdir()
    output = tmp_path / "output"
    monkeypatch.setattr(module, "_descriptor_bytes", lambda _project: b'{"descriptor":true}\n')
    for key, value in {
        "PYTHONPATH": "/ambient/python",
        "PYTHONHOME": "/ambient/home",
        "PIP_CONFIG_FILE": "/ambient/pip.conf",
        "PIP_INDEX_URL": "https://ambient.invalid",
        "AWS_PROFILE": "ambient-production",
    }.items():
        monkeypatch.setenv(key, value)
    observed = {}

    def run(arguments, **kwargs):
        observed.update(arguments=arguments, **kwargs)
        wheel_dir = Path(arguments[arguments.index("--wheel-dir") + 1])
        destination = wheel_dir / "sky_aws_vm_rehearsal_provider-0.1.0-py3-none-any.whl"
        record = "sky_aws_vm_rehearsal_provider-0.1.0.dist-info/RECORD"
        provider_path = "sky_aws_vm_rehearsal/provider.py"
        with ZipFile(destination, "w") as wheel:
            provider_source = b"provider"
            digest = base64.urlsafe_b64encode(hashlib.sha256(provider_source).digest()).rstrip(b"=").decode()
            wheel.writestr(provider_path, provider_source)
            wheel.writestr(
                record,
                f"{provider_path},sha256={digest},{len(provider_source)}\n{record},,\n".encode(),
            )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(module.subprocess, "run", run)
    destination = module.build(project, output, python=sys.executable)
    arguments = observed["arguments"]
    assert arguments[1:5] == ["-I", "-m", "pip", "wheel"]
    assert {
        "--isolated",
        "--no-index",
        "--no-input",
        "--no-cache-dir",
        "--no-deps",
        "--no-build-isolation",
    } <= set(arguments)
    assert observed["capture_output"] and observed["text"]
    assert Path(observed["cwd"]).name.startswith("sky-aws-vm-provider-")
    assert not set(observed["env"]) & {
        "PYTHONPATH",
        "PYTHONHOME",
        "PIP_CONFIG_FILE",
        "PIP_INDEX_URL",
        "AWS_PROFILE",
    }
    assert destination.is_file()


def test_wheel_finalizer_rejects_unbounded_source_entries(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "rehearsal_build_wheel_bounds", PROJECT / "tools" / "build_wheel.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source, destination = tmp_path / "source.whl", tmp_path / "destination.whl"
    record = "provider-0.1.0.dist-info/RECORD"
    with ZipFile(source, "w") as wheel:
        wheel.writestr("provider/module.py", b"too-large")
        wheel.writestr(record, f"provider/module.py,,\n{record},,\n".encode())
    monkeypatch.setattr(module, "_MAX_ENTRY_BYTES", 4)
    with pytest.raises(ValueError, match="One unfinalized"):
        module.finalize(source, destination, b"{}\n")


@pytest.mark.parametrize("record", ["wrong-digest", "wrong-size", "unlisted-file"])
def test_wheel_finalizer_rejects_source_record_drift(tmp_path, record):
    spec = importlib.util.spec_from_file_location(
        "rehearsal_build_wheel_record", PROJECT / "tools" / "build_wheel.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source, destination = tmp_path / "source.whl", tmp_path / "destination.whl"
    provider_path = "provider/module.py"
    record_path = "provider-0.1.0.dist-info/RECORD"
    content = b"provider"
    digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
    row = [provider_path, "sha256=" + digest, str(len(content))]
    if record == "wrong-digest":
        row[1] = "sha256=" + "A" * 43
    elif record == "wrong-size":
        row[2] = str(len(content) + 1)
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(row)
    writer.writerow([record_path, "", ""])
    with ZipFile(source, "w") as wheel:
        wheel.writestr(provider_path, content)
        if record == "unlisted-file":
            wheel.writestr("provider/unlisted.py", b"unlisted")
        wheel.writestr(record_path, output.getvalue().encode())
    with pytest.raises(ValueError, match="RECORD"):
        module.finalize(source, destination, b"{}\n")


def test_provider_build_cli_requires_isolated_python(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "rehearsal_build_wheel_cli", PROJECT / "tools" / "build_wheel.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(
        module,
        "sys",
        SimpleNamespace(executable=sys.executable, flags=SimpleNamespace(isolated=0)),
    )
    with pytest.raises(SystemExit) as error:
        module.main(["--output-dir", str(tmp_path)])
    assert error.value.code == 2
