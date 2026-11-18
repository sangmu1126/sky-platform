"""The provider installation verifier runs outside ambient Python, pip and AWS state."""

import base64
import csv
import hashlib
import importlib.util
import io
import os
import stat
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "providers" / "aws-vm-rehearsal" / "tools" / "verify_installation.py"


def wheel_archive(name, *, unrecorded=None, recorded_extra=None, symlink=False):
    prefix = name + "-0.1.0.dist-info"
    values = {
        name + "/__init__.py": b"",
        prefix + "/METADATA": ("Name: " + name + "\nVersion: 0.1.0\n").encode(),
        prefix + "/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    extras = (
        ()
        if recorded_extra is None
        else (recorded_extra,)
        if isinstance(recorded_extra, str)
        else recorded_extra
    )
    for extra in extras:
        values[extra] = b"target"
    record = prefix + "/RECORD"
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for path, content in sorted(values.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        writer.writerow([path, "sha256=" + digest, str(len(content))])
    writer.writerow([record, "", ""])
    values[record] = output.getvalue().encode()
    if unrecorded is not None:
        values[unrecorded] = b"import unexpected_startup_code\n"
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as wheel:
        for path, content in sorted(values.items()):
            if symlink and path == recorded_extra:
                info = zipfile.ZipInfo(path)
                info.create_system = 3
                info.external_attr = 0o120777 << 16
                wheel.writestr(info, content)
            else:
                wheel.writestr(path, content)
    return archive.getvalue()


@pytest.fixture
def verifier():
    spec = importlib.util.spec_from_file_location("provider_installation_verifier", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_two_installations_use_isolated_python_minimal_environment_and_offline_pip(
    verifier, tmp_path, monkeypatch
):
    base = tmp_path / "sky_platform-0.1.0-py3-none-any.whl"
    provider = tmp_path / "sky_aws_vm_rehearsal_provider-0.1.0-py3-none-any.whl"
    base_bytes = wheel_archive("sky_platform")
    provider_bytes = wheel_archive("sky_aws_vm_rehearsal_provider")
    base.write_bytes(base_bytes)
    provider.write_bytes(provider_bytes)
    for key, value in {
        "PYTHONPATH": "/ambient/python",
        "PYTHONHOME": "/ambient/home",
        "PIP_CONFIG_FILE": "/ambient/pip.conf",
        "PIP_INDEX_URL": "https://ambient.invalid",
        "AWS_PROFILE": "production",
        "AWS_SESSION_TOKEN": "ambient-session",
        "AWS_WEB_IDENTITY_TOKEN_FILE": "/ambient/token",
    }.items():
        monkeypatch.setenv(key, value)

    calls = []
    artifact = "a" * 64
    execution = "b" * 64
    manifest = {
        "provider_artifact_sha256": artifact,
        "registrations": [
            {
                "execution_revision": execution,
                "resource_verifier_ref": "RVR-registered",
                "effect_ref": "EEF-registered",
            }
        ],
    }

    def run(arguments, *, env, cwd):
        calls.append((arguments, env, Path(cwd)))
        if "pip" in arguments:
            site = Path(arguments[arguments.index("--target") + 1])
            assert stat.S_IMODE(site.stat().st_mode) == 0o700
            package = site / "sky_aws_vm_rehearsal"
            package.mkdir()
            package.chmod(0o700)
            return ""
        script = arguments[-1]
        if "interfaces.b_runtime" in script:
            return verifier._CHECK_CONFIG_OUTPUT
        if "environment_execution_registration" in script:
            return (
                '{"artifact":"' + artifact + '","bytecode":true,"count":1,"effect":"EEF-registered",'
                '"resource":"RVR-registered","secrets":6,'
                '"runtime_pin":"ETR-registered","runtime_impl":"ETR-registered",'
                '"resolver_pin":"ESR-registered","resolver_impl":"ESR-registered",'
                '"composer_pin":"RTC-registered","composer_impl":"RTC-registered",'
                '"execution":"'
                + execution
                + '","runtime_execution":"'
                + execution
                + '","composer_execution":"'
                + execution
                + '"}'
            )
        if "environment_execution_provider" in script:
            return '{"provider_artifact_sha256":"' + artifact + '"}'
        if "environment_execution_manifest" in script:
            import json

            return json.dumps(manifest)
        raise AssertionError("Unexpected verifier subprocess")

    monkeypatch.setattr(verifier, "_run", run)
    previous = os.umask(0o777)
    try:
        result = verifier.verify(base, provider, python=sys.executable)
    finally:
        os.umask(previous)

    assert result["base_wheel_sha256"] == hashlib.sha256(base_bytes).hexdigest()
    assert result["provider_wheel_sha256"] == hashlib.sha256(provider_bytes).hexdigest()
    assert result["runtime_chain_pins_match"] is True
    assert result["worker_check_config_without_external_calls"] is True
    pip_calls = [call for call in calls if "pip" in call[0]]
    inspect_calls = [call for call in calls if "pip" not in call[0]]
    assert len(pip_calls) == 2 and len(inspect_calls) == 8
    for arguments, env, cwd in pip_calls:
        assert arguments[1:4] == ["-I", "-m", "pip"]
        assert {"--isolated", "--no-index", "--no-input", "--no-cache-dir", "--no-deps"} <= set(arguments)
        assert cwd.name.startswith("sky-provider-installation-")
        assert not set(env) & {
            "PYTHONPATH",
            "PYTHONHOME",
            "PIP_CONFIG_FILE",
            "PIP_INDEX_URL",
            "AWS_PROFILE",
            "AWS_SESSION_TOKEN",
        }
    for arguments, env, cwd in inspect_calls:
        assert arguments[1:3] == ["-I", "-c"]
        assert "sys.path.insert(0," in arguments[-1]
        assert cwd.name.startswith("sky-provider-installation-")
        assert env["AWS_EC2_METADATA_DISABLED"] == "true"
        assert env["AWS_ACCESS_KEY_ID"] == "isolated-installation-check"
        assert env["AWS_SECRET_ACCESS_KEY"] == "isolated-installation-check"
        assert env["HOME"] == str(cwd)
        assert env["AWS_CONFIG_FILE"] == str(cwd / "aws-config-disabled")
        assert env["AWS_SHARED_CREDENTIALS_FILE"] == str(cwd / "aws-credentials-disabled")
        assert env["BOTO_CONFIG"] == str(cwd / "boto-config-disabled")
        assert not set(env) & {
            "PYTHONPATH",
            "PYTHONHOME",
            "PIP_CONFIG_FILE",
            "PIP_INDEX_URL",
            "AWS_PROFILE",
            "AWS_SESSION_TOKEN",
            "AWS_WEB_IDENTITY_TOKEN_FILE",
        }


def test_verifier_requires_an_absolute_executable_python(verifier, tmp_path):
    with pytest.raises(ValueError, match="Absolute executable"):
        verifier.verify(tmp_path / "base", tmp_path / "provider", python="python")


@pytest.mark.parametrize(
    "value",
    [
        '{"value":1,"value":2}',
        '{"nested":{"value":1,"value":2}}',
        '{"value":NaN}',
        '{"value":Infinity}',
        '{"value":1e999}',
        "[]",
    ],
)
def test_verifier_rejects_ambiguous_or_non_object_subprocess_json(verifier, value):
    with pytest.raises((TypeError, ValueError)):
        verifier._strict_json(value, maximum=1024)


def test_verifier_rejects_unbounded_subprocess_json(verifier):
    with pytest.raises(ValueError, match="Bounded"):
        verifier._strict_json('{"value":"' + "x" * 1024 + '"}', maximum=128)


def test_verifier_creates_private_files_without_following_existing_paths(verifier, tmp_path):
    target = tmp_path / "manifest.json"
    previous = os.umask(0o777)
    try:
        verifier._private_text_file(target, '{"schema_version":1}', maximum=1024)
    finally:
        os.umask(previous)
    assert target.read_text() == '{"schema_version":1}'
    assert stat.S_IMODE(target.stat().st_mode) == 0o400
    with pytest.raises(ValueError, match="creation failed"):
        verifier._private_text_file(target, "replacement", maximum=1024)
    link = tmp_path / "state.pem"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="creation failed"):
        verifier._private_text_file(link, "replacement", maximum=1024)


def test_verifier_rejects_writable_private_file_parent(verifier, tmp_path):
    tmp_path.chmod(0o777)
    with pytest.raises(ValueError, match="Private verifier directory"):
        verifier._private_text_file(tmp_path / "manifest.json", "{}", maximum=1024)


def test_verifier_subprocess_has_timeout_bounded_file_capture_and_utf8(verifier, tmp_path, monkeypatch):
    observed = {}

    def run(arguments, **kwargs):
        observed.update(arguments=arguments, **kwargs)
        kwargs["stdout"].write(b"verified\n")
        kwargs["stderr"].write(b"diagnostic")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(verifier.subprocess, "run", run)
    assert verifier._run(["provider-check"], env={}, cwd=tmp_path) == "verified"
    assert observed["check"] is True and observed["timeout"] == verifier._SUBPROCESS_TIMEOUT
    assert observed["umask"] == 0o077
    assert "capture_output" not in observed and "text" not in observed


def test_verifier_subprocess_rejects_oversized_or_non_utf8_stdout(verifier, tmp_path, monkeypatch):
    def oversized(_arguments, **kwargs):
        kwargs["stdout"].write(b"x" * (verifier._MAX_SUBPROCESS_OUTPUT + 1))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(verifier.subprocess, "run", oversized)
    with pytest.raises(ValueError, match="Bounded"):
        verifier._run(["provider-check"], env={}, cwd=tmp_path)

    def non_utf8(_arguments, **kwargs):
        kwargs["stdout"].write(b"\xff")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(verifier.subprocess, "run", non_utf8)
    with pytest.raises(ValueError, match="UTF-8"):
        verifier._run(["provider-check"], env={}, cwd=tmp_path)


def test_verifier_pinned_wheel_copy_has_exact_mode_under_restrictive_umask(verifier, tmp_path):
    source = tmp_path / "sky_platform-0.1.0-py3-none-any.whl"
    source.write_bytes(wheel_archive("sky_platform"))
    copies = tmp_path / "copies"
    copies.mkdir()
    previous = os.umask(0o777)
    try:
        destination, _digest = verifier._private_wheel(copies, source)
    finally:
        os.umask(previous)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o400


def test_verifier_rejects_unrecorded_wheel_file_before_pip(verifier, tmp_path):
    source = tmp_path / "sky_platform-0.1.0-py3-none-any.whl"
    source.write_bytes(wheel_archive("sky_platform", unrecorded="unexpected-data.bin"))
    copies = tmp_path / "copies"
    copies.mkdir()

    with pytest.raises(ValueError, match="RECORD differs"):
        verifier._private_wheel(copies, source)

    assert not tuple(copies.iterdir())


@pytest.mark.parametrize(
    "content",
    [
        wheel_archive("sky_platform", recorded_extra="unsafe\nname"),
        wheel_archive("sky_platform", recorded_extra="linked-file", symlink=True),
    ],
)
def test_verifier_rejects_noncanonical_or_nonregular_wheel_entries(verifier, content):
    with pytest.raises(ValueError, match="canonical|Canonical"):
        verifier._verify_wheel_archive(content)


@pytest.mark.parametrize(
    "path",
    [
        "reviewed-provider.pth",
        "distribution.data/purelib/sitecustomize.py",
        "usercustomize/__init__.py",
    ],
)
def test_verifier_rejects_recorded_python_startup_hooks(verifier, path):
    content = wheel_archive("sky_platform", recorded_extra=path)

    with pytest.raises(ValueError, match="canonical"):
        verifier._verify_wheel_archive(content)


def test_verifier_rejects_portable_wheel_path_collisions(verifier):
    content = wheel_archive("sky_platform", recorded_extra=("Collision.py", "collision.py"))

    with pytest.raises(ValueError, match="canonical"):
        verifier._verify_wheel_archive(content)


def test_verifier_rejects_symlink_or_writable_wheel_before_pip(verifier, tmp_path):
    wheel = tmp_path / "sky_platform-0.1.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    link = tmp_path / "sky_platform-0.2.0-py3-none-any.whl"
    link.symlink_to(wheel)
    with pytest.raises(ValueError, match="Exactly one expected"):
        verifier._wheel(link, "sky_platform")
    wheel.chmod(0o666)
    with pytest.raises(ValueError, match="Immutable bounded"):
        verifier._wheel_bytes(wheel)


def test_verifier_cli_requires_isolated_python(verifier, tmp_path, monkeypatch):
    monkeypatch.setattr(
        verifier,
        "sys",
        SimpleNamespace(executable=sys.executable, flags=SimpleNamespace(isolated=0)),
    )
    with pytest.raises(SystemExit) as error:
        verifier.main(
            [
                "--base-wheel",
                str(tmp_path / "base.whl"),
                "--provider-wheel",
                str(tmp_path / "provider.whl"),
            ]
        )
    assert error.value.code == 2
