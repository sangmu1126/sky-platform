"""Verify two path-independent, bytecode-free installations of reviewed provider wheels."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import math
import os
import stat
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path, PurePosixPath
from zipfile import BadZipFile, ZipFile

PROVIDER = "sky-aws-vm-rehearsal"
WORKSPACE = "isolated-rehearsal"
_ENVIRONMENT_KEYS = ("LANG", "LC_ALL", "PATH", "SYSTEMROOT")
_MAX_WHEEL_BYTES = 256 * 1024 * 1024
_MAX_WHEEL_ENTRIES = 2048
_MAX_SUBPROCESS_OUTPUT = 2 * 1024 * 1024
_SUBPROCESS_TIMEOUT = 60
_CHECK_CONFIG_OUTPUT = (
    "Reviewed environment worker configuration valid; provider code, AWS and DB were not called"
)
_NETWORK_GUARD = """
import socket as _sky_socket
class _SkyNoNetworkSocket(_sky_socket.socket):
    def _deny(self, *args, **kwargs):
        raise RuntimeError("Network disabled during provider verification")
    connect = connect_ex = sendto = sendmsg = bind = listen = _deny
_sky_socket.socket = _SkyNoNetworkSocket
def _sky_no_network(*args, **kwargs):
    raise RuntimeError("Network disabled during provider verification")
_sky_socket.create_connection = _sky_no_network
_sky_socket.getaddrinfo = _sky_no_network
"""


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate verifier JSON field")
        value[key] = item
    return value


def _finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("Finite verifier JSON number required")
    return result


def _reject_constant(_value):
    raise ValueError("Standard verifier JSON required")


def _strict_json(value, *, maximum):
    if not isinstance(value, str) or not 1 <= len(value.encode()) <= maximum:
        raise ValueError("Bounded verifier JSON required")
    result = json.loads(
        value,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
        parse_float=_finite_float,
    )
    if not isinstance(result, dict):
        raise TypeError("Verifier JSON object required")
    return result


def _run(arguments, *, env, cwd):
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        subprocess.run(
            arguments,
            check=True,
            stdout=output,
            stderr=errors,
            env=env,
            cwd=cwd,
            timeout=_SUBPROCESS_TIMEOUT,
            umask=0o077,
        )
        output.seek(0, os.SEEK_END)
        errors.seek(0, os.SEEK_END)
        if output.tell() > _MAX_SUBPROCESS_OUTPUT or errors.tell() > _MAX_SUBPROCESS_OUTPUT:
            raise ValueError("Bounded provider verification subprocess output required")
        output.seek(0)
        try:
            return output.read().decode("utf-8").strip()
        except UnicodeDecodeError:
            raise ValueError("UTF-8 provider verification subprocess output required") from None


def _environment(**overrides):
    value = {key: os.environ[key] for key in _ENVIRONMENT_KEYS if key in os.environ}
    value.update(overrides)
    return value


def _python(value):
    path = Path(value)
    if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError("Absolute executable verification Python required")
    return str(path)


def _isolated_python(python, site, script):
    bootstrap = f"import sys\nsys.path.insert(0,{str(site)!r})\n{_NETWORK_GUARD}\n"
    return [python, "-I", "-c", bootstrap + script]


def _wheel(value, prefix):
    path = Path(value).absolute()
    matches = tuple(path.glob(prefix + "-*.whl")) if path.is_dir() else (path,)
    if len(matches) != 1 or matches[0].suffix != ".whl" or not matches[0].name.startswith(prefix + "-"):
        raise ValueError("Exactly one expected provider installation wheel required")
    try:
        metadata = matches[0].lstat()
    except OSError:
        raise ValueError("Exactly one expected provider installation wheel required") from None
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("Exactly one expected provider installation wheel required")
    return matches[0]


def _wheel_bytes(path):
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError:
        raise ValueError("Immutable bounded provider installation wheel required") from None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 1 <= before.st_size <= _MAX_WHEEL_BYTES
        ):
            raise ValueError("Immutable bounded provider installation wheel required")
        content = bytearray()
        while len(content) <= _MAX_WHEEL_BYTES:
            chunk = os.read(descriptor, min(1024 * 1024, _MAX_WHEEL_BYTES + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        if len(content) != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ValueError("Provider installation wheel changed while reading")
        data = bytes(content)
        return data, hashlib.sha256(data).hexdigest()
    finally:
        os.close(descriptor)


def _wheel_path(name):
    value = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or "\x00" in name
        or name.endswith("/")
        or name != value.as_posix()
        or value.is_absolute()
        or any(part in {"", ".", ".."} for part in value.parts)
        or any(ord(character) < 33 for character in name)
        or len(name.encode()) > 512
    ):
        raise ValueError("Canonical provider installation wheel path required")
    return name


def _wheel_startup_hook(name):
    value = PurePosixPath(name)
    return (
        value.suffix in {".pth", ".egg-link"}
        or value.name in {"sitecustomize.py", "usercustomize.py"}
        or any(part in {"sitecustomize", "usercustomize"} for part in value.parts)
    )


def _verify_wheel_archive(data):
    try:
        with ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            names = [_wheel_path(value.filename) for value in infos]
            portable_names = [unicodedata.normalize("NFC", name).casefold() for name in names]
            records = [name for name in names if name.endswith(".dist-info/RECORD")]
            if (
                not 1 <= len(infos) <= _MAX_WHEEL_ENTRIES
                or len(names) != len(set(names))
                or len(portable_names) != len(set(portable_names))
                or len(records) != 1
                or any(_wheel_startup_hook(name) for name in names)
                or any(
                    value.flag_bits & 1
                    or value.is_dir()
                    or stat.S_IFMT(value.external_attr >> 16) not in {0, stat.S_IFREG}
                    or value.file_size > _MAX_WHEEL_BYTES
                    or value.compress_size > _MAX_WHEEL_BYTES
                    for value in infos
                )
                or sum(value.file_size for value in infos) > _MAX_WHEEL_BYTES
            ):
                raise ValueError("Bounded canonical provider installation wheel required")
            values = {value.filename: archive.read(value) for value in infos}
    except (BadZipFile, OSError, RuntimeError):
        raise ValueError("Readable provider installation wheel archive required") from None
    record_path = records[0]
    try:
        rows = list(csv.reader(io.StringIO(values[record_path].decode("utf-8"))))
    except (UnicodeError, csv.Error):
        raise ValueError("Canonical provider installation wheel RECORD required") from None
    recorded = {}
    for row in rows:
        if len(row) != 3:
            raise ValueError("Canonical provider installation wheel RECORD required")
        name, digest, size = row
        _wheel_path(name)
        if name in recorded or name not in values:
            raise ValueError("Canonical provider installation wheel RECORD required")
        if name == record_path:
            if digest or size:
                raise ValueError("Canonical provider installation wheel RECORD required")
        else:
            content = values[name]
            expected = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
            if digest != "sha256=" + expected or size != str(len(content)):
                raise ValueError("Provider installation wheel RECORD differs from archive")
        recorded[name] = (digest, size)
    if set(recorded) != set(values):
        raise ValueError("Provider installation wheel RECORD differs from archive")


def _private_wheel(root, source):
    data, digest = _wheel_bytes(source)
    _verify_wheel_archive(data)
    destination = root / source.name
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        0o400,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            os.fchmod(output.fileno(), 0o400)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)
    return destination, digest


def _private_text_file(path, content, *, maximum):
    if (
        not isinstance(content, str)
        or not 1 <= len(content.encode()) <= maximum
        or path.name in {"", ".", ".."}
        or path.parent == path
    ):
        raise ValueError("Bounded private verifier file required")
    directory = os.open(
        path.parent,
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        metadata = os.fstat(directory)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise ValueError("Private verifier directory required")
        descriptor = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            0o400,
            dir_fd=directory,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as output:
                os.fchmod(output.fileno(), 0o400)
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
        finally:
            os.close(descriptor)
        os.fsync(directory)
    except OSError:
        raise ValueError("Private verifier file creation failed") from None
    finally:
        os.close(directory)


def _provider_cache_absent(site):
    package = site / "sky_aws_vm_rehearsal"
    return package.is_dir() and not any(
        value.name == "__pycache__" or value.suffix == ".pyc" for value in package.rglob("*")
    )


def _seal_installation(site):
    values = sorted(site.rglob("*"), key=lambda value: len(value.parts), reverse=True)
    for value in values:
        metadata = value.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("Provider installation symlinks are forbidden")
        if stat.S_ISREG(metadata.st_mode):
            value.chmod(0o400)
        elif stat.S_ISDIR(metadata.st_mode):
            value.chmod(0o500)
        else:
            raise ValueError("Plain provider installation tree required")
    site.chmod(0o500)


def _unseal_directories(site):
    site.chmod(0o700)
    for value in site.rglob("*"):
        if value.is_dir() and not value.is_symlink():
            value.chmod(0o700)


def _inspect(python, site, workspace, manifest, *, cwd):
    private_home = str(Path(cwd))
    env = _environment(
        HOME=private_home,
        AWS_EC2_METADATA_DISABLED="true",
        AWS_ACCESS_KEY_ID="isolated-installation-check",
        AWS_SECRET_ACCESS_KEY="isolated-installation-check",
        AWS_DEFAULT_REGION="ap-northeast-2",
        AWS_CONFIG_FILE=str(Path(cwd) / "aws-config-disabled"),
        AWS_SHARED_CREDENTIALS_FILE=str(Path(cwd) / "aws-credentials-disabled"),
        BOTO_CONFIG=str(Path(cwd) / "boto-config-disabled"),
    )
    artifact = _strict_json(
        _run(
            _isolated_python(
                python,
                site,
                (
                    "from interfaces.environment_execution_provider import main;"
                    f"main(['--provider','{PROVIDER}'])"
                ),
            ),
            env=env,
            cwd=cwd,
        ),
        maximum=65536,
    )
    document = _strict_json(
        _run(
            _isolated_python(
                python,
                site,
                (
                    "from interfaces.environment_execution_manifest import main;"
                    f"main(['--provider','{PROVIDER}','--workspace','{workspace}'])"
                ),
            ),
            env=env,
            cwd=cwd,
        ),
        maximum=1024 * 1024,
    )
    _private_text_file(
        manifest,
        json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False),
        maximum=1024 * 1024,
    )
    state_ca = manifest.with_name("state-ca-" + site.name + ".pem")
    _private_text_file(state_ca, "isolated-check-ca\n", maximum=1024)
    check_env = {
        **env,
        "SKY_DATABASE_HOST": "state.rehearsal.invalid",
        "SKY_DATABASE_NAME": "sky_state",
        "SKY_DATABASE_SECRET_ARN": (
            "arn:aws:secretsmanager:ap-northeast-2:000000000000:secret:isolated-check"
        ),
        "SKY_DATABASE_SSLROOTCERT": str(state_ca),
        "SKY_AWS_REGION": "ap-northeast-2",
        "SKY_AWS_ACCOUNT_ID": "000000000000",
        "SKY_STATE_WORKSPACE": workspace,
        "SKY_ENVIRONMENT_EXECUTION_QUEUE_URL": (
            "https://sqs.ap-northeast-2.amazonaws.com/000000000000/isolated-environment.fifo"
        ),
        "SKY_ALB_TRUSTS_JSON": json.dumps(
            {
                "version": 1,
                "trusts": [
                    {
                        "signer_arn": (
                            "arn:aws:elasticloadbalancing:ap-northeast-2:000000000000:"
                            "loadbalancer/app/isolated-check/0123456789abcdef"
                        ),
                        "issuer": "https://identity.rehearsal.invalid/",
                        "client_id": "isolated-check",
                        "login_source": "corporate_sso",
                    }
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        "SKY_MEMBERSHIPS_JSON": '{"members":[],"version":1}',
    }
    check_config = _run(
        _isolated_python(
            python,
            site,
            (
                "from interfaces.b_runtime import main;"
                "main(['worker','--mode','environment-execution',"
                f"'--environment-execution-config',{str(manifest)!r},'--check-config'])"
            ),
        ),
        env=check_env,
        cwd=cwd,
    )
    if check_config != _CHECK_CONFIG_OUTPUT or not _provider_cache_absent(site):
        raise ValueError("Worker check-config imported provider code or changed external state")
    result = _strict_json(
        _run(
            _isolated_python(
                python,
                site,
                (
                    "import json,sys;"
                    "from interfaces.environment_execution_registration import "
                    "load_environment_execution_manifest,compose_environment_executions,"
                    "attest_environment_execution_provider,environment_execution_entry_points;"
                    f"m=load_environment_execution_manifest({str(manifest)!r},workspace={workspace!r});"
                    "c=compose_environment_executions(m);"
                    "e=environment_execution_entry_points(m.provider)[0];"
                    "print(json.dumps({'count':len(c),"
                    "'secrets':len(c[0].effect.runtime.registration.secrets),"
                    "'resource':c[0].resource_verifier_ref,'effect':c[0].effect_ref,"
                    "'runtime_pin':c[0].effect.runtime_ref,"
                    "'runtime_impl':c[0].effect.runtime.reference,"
                    "'resolver_pin':c[0].effect.runtime.registration.secret_resolver_ref,"
                    "'resolver_impl':c[0].effect.runtime.resolver.reference,"
                    "'composer_pin':c[0].effect.runtime.registration.composition_ref,"
                    "'composer_impl':c[0].effect.runtime.composer.reference,"
                    "'execution':c[0].execution.revision,"
                    "'runtime_execution':c[0].effect.runtime.execution.revision,"
                    "'composer_execution':c[0].effect.runtime.composer.execution.revision,"
                    "'artifact':attest_environment_execution_provider(e).artifact_sha256,"
                    "'bytecode':sys.dont_write_bytecode},sort_keys=True))"
                ),
            ),
            env=env,
            cwd=cwd,
        ),
        maximum=65536,
    )
    return artifact, document, result, check_config


def verify(base_wheel, provider_wheel, *, python=sys.executable):
    python = _python(python)
    sources = (
        _wheel(base_wheel, "sky_platform"),
        _wheel(provider_wheel, "sky_aws_vm_rehearsal_provider"),
    )
    observations = []
    with tempfile.TemporaryDirectory(prefix="sky-provider-installation-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        pinned = tuple(_private_wheel(root, value) for value in sources)
        wheels = tuple(value[0] for value in pinned)
        wheel_digests = tuple(value[1] for value in pinned)
        for name in ("one", "two"):
            site = root / name
            site.mkdir(mode=0o700)
            site.chmod(0o700)
            _run(
                [
                    python,
                    "-I",
                    "-m",
                    "pip",
                    "install",
                    "--isolated",
                    "--disable-pip-version-check",
                    "--no-index",
                    "--no-input",
                    "--no-cache-dir",
                    "--no-compile",
                    "--no-deps",
                    "--target",
                    str(site),
                    *(str(value) for value in wheels),
                ],
                env=_environment(),
                cwd=root,
            )
            _seal_installation(site)
            try:
                if not _provider_cache_absent(site):
                    raise ValueError("Provider installation must not contain bytecode")
                observations.append(
                    _inspect(
                        python,
                        site,
                        WORKSPACE,
                        root / f"manifest-{name}.json",
                        cwd=root,
                    )
                )
                if not _provider_cache_absent(site):
                    raise ValueError("Provider import created bytecode")
            finally:
                _unseal_directories(site)
    if observations[0] != observations[1]:
        raise ValueError("Provider installation differs by target path")
    artifact, manifest, composition, check_config = observations[0]
    if (
        artifact.get("provider_artifact_sha256") != manifest.get("provider_artifact_sha256")
        or composition.get("artifact") != artifact.get("provider_artifact_sha256")
        or composition.get("count") != 1
        or composition.get("secrets") != 6
        or composition.get("resource") != manifest["registrations"][0]["resource_verifier_ref"]
        or composition.get("effect") != manifest["registrations"][0]["effect_ref"]
        or composition.get("runtime_pin") != composition.get("runtime_impl")
        or composition.get("resolver_pin") != composition.get("resolver_impl")
        or composition.get("composer_pin") != composition.get("composer_impl")
        or composition.get("execution") != manifest["registrations"][0]["execution_revision"]
        or len(
            {
                composition.get("execution"),
                composition.get("runtime_execution"),
                composition.get("composer_execution"),
            }
        )
        != 1
        or composition.get("bytecode") is not True
        or check_config != _CHECK_CONFIG_OUTPUT
    ):
        raise ValueError("Installed provider composition differs from secret-free pins")
    return {
        "schema_version": 1,
        "profile": "isolated_environment_provider_installation_v1",
        "provider": PROVIDER,
        "base_wheel_sha256": wheel_digests[0],
        "provider_wheel_sha256": wheel_digests[1],
        "provider_artifact_sha256": artifact["provider_artifact_sha256"],
        "registrations": composition["count"],
        "runtime_secret_purposes": composition["secrets"],
        "runtime_chain_pins_match": True,
        "provider_code_imported_only_after_manifest": True,
        "worker_check_config_without_external_calls": True,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--base-wheel", required=True)
    parser.add_argument("--provider-wheel", required=True)
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args(argv)
    if not sys.flags.isolated:
        parser.exit(2, "Provider installation verification requires Python isolated mode (-I).\n")
    try:
        result = verify(args.base_wheel, args.provider_wheel, python=args.python)
    except Exception:  # noqa: BLE001 -- temporary paths and provider diagnostics remain private
        parser.exit(1, "Isolated environment provider installation verification failed.\n")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
