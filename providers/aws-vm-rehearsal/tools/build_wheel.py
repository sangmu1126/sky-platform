"""Build and finalize the rehearsal provider wheel with its dist-info descriptor."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

DESCRIPTOR = "sky-environment-executions-v1.json"


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


def _record_with_descriptor(record, descriptor_path, descriptor):
    rows = list(csv.reader(io.StringIO(record.decode())))
    record_rows = [value for value in rows if value and value[0].endswith(".dist-info/RECORD")]
    if len(record_rows) != 1 or any(value and value[0] == descriptor_path for value in rows):
        raise ValueError("Canonical provider wheel RECORD required")
    digest = base64.urlsafe_b64encode(hashlib.sha256(descriptor).digest()).rstrip(b"=").decode()
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for row in rows:
        if row is record_rows[0]:
            writer.writerow([descriptor_path, "sha256=" + digest, str(len(descriptor))])
        writer.writerow(row)
    return output.getvalue().encode()


def finalize(source, destination, descriptor):
    with ZipFile(source) as wheel:
        infos = wheel.infolist()
        names = [value.filename for value in infos]
        records = [value for value in names if value.endswith(".dist-info/RECORD")]
        if len(records) != 1 or any(value.endswith(".dist-info/" + DESCRIPTOR) for value in names):
            raise ValueError("One unfinalized provider wheel required")
        record_path = records[0]
        descriptor_path = record_path.rsplit("/", 1)[0] + "/" + DESCRIPTOR
        values = {value.filename: wheel.read(value.filename) for value in infos}
    values[record_path] = _record_with_descriptor(
        values[record_path],
        descriptor_path,
        descriptor,
    )
    descriptor_info = ZipInfo(descriptor_path, date_time=(1980, 1, 1, 0, 0, 0))
    descriptor_info.compress_type = ZIP_DEFLATED
    descriptor_info.external_attr = 0o100644 << 16
    with ZipFile(destination, "x", compression=ZIP_DEFLATED) as wheel:
        for info in infos:
            wheel.writestr(info, values[info.filename])
        wheel.writestr(descriptor_info, descriptor)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    project = Path(__file__).resolve().parents[1]
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    descriptor = _descriptor_bytes(project)
    with tempfile.TemporaryDirectory(prefix="sky-aws-vm-provider-") as temporary:
        subprocess.run(
            [
                args.python,
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--no-build-isolation",
                "--wheel-dir",
                temporary,
                str(project),
            ],
            check=True,
        )
        wheels = list(Path(temporary).glob("*.whl"))
        if len(wheels) != 1:
            raise ValueError("Exactly one provider wheel required")
        destination = output / wheels[0].name
        finalize(wheels[0], destination, descriptor)
    print(destination)


if __name__ == "__main__":
    main()
