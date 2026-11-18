"""Build and finalize the rehearsal provider wheel with its dist-info descriptor."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

DESCRIPTOR = "sky-environment-executions-v1.json"
_WHEEL_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_ENVIRONMENT_KEYS = ("LANG", "LC_ALL", "PATH", "SYSTEMROOT")
_MAX_ENTRY_BYTES = 32 * 1024 * 1024
_MAX_WHEEL_BYTES = 64 * 1024 * 1024


def _environment():
    return {key: os.environ[key] for key in _ENVIRONMENT_KEYS if key in os.environ}


def _python(value):
    path = Path(value)
    if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError("Absolute executable provider build Python required")
    return str(path)


def _expected_descriptor(project):
    repository = project.parents[1]
    sys.path[:0] = [str(repository / "src"), str(project / "src")]
    from sky_aws_vm_rehearsal.provider import PROVIDER, provider_pins

    return {
        "schema_version": 1,
        "profile": "reviewed_environment_provider_executions_v1",
        "provider": PROVIDER,
        "registrations": [provider_pins()],
    }


def _descriptor_bytes(project):
    path = project / "descriptor" / DESCRIPTOR
    raw = path.read_bytes()
    value = json.loads(raw)
    if value != _expected_descriptor(project):
        raise ValueError("Provider descriptor differs from composed public pins")
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    if raw.rstrip(b"\n") != canonical:
        raise ValueError("Canonical provider descriptor required")
    return canonical + b"\n"


def _record_with_descriptor(record, record_path, descriptor_path, descriptor, values):
    rows = list(csv.reader(io.StringIO(record.decode())))
    if any(len(row) != 3 for row in rows):
        raise ValueError("Canonical provider wheel RECORD required")
    recorded = {}
    for row in rows:
        name, digest, size = row
        _canonical_info(name)
        if name in recorded or name not in values:
            raise ValueError("Canonical provider wheel RECORD required")
        if name == record_path:
            if digest or size:
                raise ValueError("Canonical provider wheel RECORD required")
        else:
            content = values[name]
            expected = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
            if digest != "sha256=" + expected or size != str(len(content)):
                raise ValueError("Provider source wheel RECORD differs from archive contents")
        recorded[name] = row
    if set(recorded) != set(values) or descriptor_path in recorded:
        raise ValueError("Canonical provider wheel RECORD required")
    digest = base64.urlsafe_b64encode(hashlib.sha256(descriptor).digest()).rstrip(b"=").decode()
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for row in rows:
        if row[0] == record_path:
            writer.writerow([descriptor_path, "sha256=" + digest, str(len(descriptor))])
        writer.writerow(row)
    return output.getvalue().encode()


def _canonical_info(name):
    path = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or "\x00" in name
        or name.endswith("/")
        or name != path.as_posix()
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or len(name) > 512
    ):
        raise ValueError("Canonical provider wheel path required")
    info = ZipInfo(name, date_time=_WHEEL_TIMESTAMP)
    info.compress_type = ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info


def finalize(source, destination, descriptor):
    with ZipFile(source) as wheel:
        infos = wheel.infolist()
        names = [value.filename for value in infos]
        records = [value for value in names if value.endswith(".dist-info/RECORD")]
        if (
            not 1 <= len(infos) <= 512
            or len(names) != len(set(names))
            or len(records) != 1
            or any(value.endswith(".dist-info/" + DESCRIPTOR) for value in names)
            or any(
                value.flag_bits & 1
                or value.is_dir()
                or value.file_size > _MAX_ENTRY_BYTES
                or value.compress_size > _MAX_ENTRY_BYTES
                for value in infos
            )
            or sum(value.file_size for value in infos) > _MAX_WHEEL_BYTES
        ):
            raise ValueError("One unfinalized provider wheel required")
        for name in names:
            _canonical_info(name)
        record_path = records[0]
        descriptor_path = record_path.rsplit("/", 1)[0] + "/" + DESCRIPTOR
        values = {value.filename: wheel.read(value.filename) for value in infos}
    values[record_path] = _record_with_descriptor(
        values[record_path],
        record_path,
        descriptor_path,
        descriptor,
        values,
    )
    values[descriptor_path] = descriptor
    with ZipFile(destination, "x", compression=ZIP_DEFLATED) as wheel:
        for name in sorted(values):
            wheel.writestr(_canonical_info(name), values[name])


def build(project, output, *, python=sys.executable):
    python = _python(python)
    project = Path(project).resolve(strict=True)
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    descriptor = _descriptor_bytes(project)
    with tempfile.TemporaryDirectory(prefix="sky-aws-vm-provider-") as temporary:
        subprocess.run(
            [
                python,
                "-I",
                "-m",
                "pip",
                "wheel",
                "--isolated",
                "--disable-pip-version-check",
                "--no-index",
                "--no-input",
                "--no-cache-dir",
                "--no-deps",
                "--no-build-isolation",
                "--wheel-dir",
                temporary,
                str(project),
            ],
            check=True,
            capture_output=True,
            text=True,
            env=_environment(),
            cwd=temporary,
        )
        wheels = list(Path(temporary).glob("*.whl"))
        if len(wheels) != 1:
            raise ValueError("Exactly one provider wheel required")
        destination = output / wheels[0].name
        finalize(wheels[0], destination, descriptor)
    return destination


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    if not sys.flags.isolated:
        parser.exit(2, "Provider wheel build requires Python isolated mode (-I).\n")
    project = Path(__file__).resolve().parents[1]
    destination = build(project, args.output_dir, python=args.python)
    print(destination)


if __name__ == "__main__":
    main()
