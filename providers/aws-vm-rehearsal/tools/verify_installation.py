"""Verify two path-independent, bytecode-free installations of reviewed provider wheels."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

PROVIDER = "sky-aws-vm-rehearsal"
WORKSPACE = "isolated-rehearsal"


def _run(arguments, *, env=None):
    return subprocess.run(
        arguments,
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout.strip()


def _wheel(value, prefix):
    path = Path(value).resolve(strict=True)
    matches = tuple(path.glob(prefix + "-*.whl")) if path.is_dir() else (path,)
    if (
        len(matches) != 1
        or not matches[0].is_file()
        or matches[0].suffix != ".whl"
        or not matches[0].name.startswith(prefix + "-")
    ):
        raise ValueError("Exactly one expected provider installation wheel required")
    return matches[0]


def _provider_cache_absent(site):
    package = site / "sky_aws_vm_rehearsal"
    return package.is_dir() and not any(
        value.name == "__pycache__" or value.suffix == ".pyc" for value in package.rglob("*")
    )


def _inspect(python, site, workspace, manifest):
    env = {
        **os.environ,
        "PYTHONPATH": str(site),
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_ACCESS_KEY_ID": "isolated-installation-check",
        "AWS_SECRET_ACCESS_KEY": "isolated-installation-check",
        "AWS_DEFAULT_REGION": "ap-northeast-2",
    }
    artifact = json.loads(
        _run(
            [
                python,
                "-c",
                (
                    "from interfaces.environment_execution_provider import main;"
                    f"main(['--provider','{PROVIDER}'])"
                ),
            ],
            env=env,
        )
    )
    document = json.loads(
        _run(
            [
                python,
                "-c",
                (
                    "from interfaces.environment_execution_manifest import main;"
                    f"main(['--provider','{PROVIDER}','--workspace','{workspace}'])"
                ),
            ],
            env=env,
        )
    )
    manifest.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")))
    result = json.loads(
        _run(
            [
                python,
                "-c",
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
                    "'artifact':attest_environment_execution_provider(e).artifact_sha256,"
                    "'bytecode':sys.dont_write_bytecode},sort_keys=True))"
                ),
            ],
            env=env,
        )
    )
    return artifact, document, result


def verify(base_wheel, provider_wheel, *, python=sys.executable):
    wheels = (
        _wheel(base_wheel, "sky_platform"),
        _wheel(provider_wheel, "sky_aws_vm_rehearsal_provider"),
    )
    observations = []
    with tempfile.TemporaryDirectory(prefix="sky-provider-installation-") as temporary:
        root = Path(temporary)
        for name in ("one", "two"):
            site = root / name
            site.mkdir(mode=0o700)
            _run(
                [
                    python,
                    "-m",
                    "pip",
                    "install",
                    "--disable-pip-version-check",
                    "--no-compile",
                    "--no-deps",
                    "--target",
                    str(site),
                    *(str(value) for value in wheels),
                ]
            )
            if not _provider_cache_absent(site):
                raise ValueError("Provider installation must not contain bytecode")
            observations.append(_inspect(python, site, WORKSPACE, root / f"manifest-{name}.json"))
            if not _provider_cache_absent(site):
                raise ValueError("Provider import created bytecode")
    if observations[0] != observations[1]:
        raise ValueError("Provider installation differs by target path")
    artifact, manifest, composition = observations[0]
    if (
        artifact.get("provider_artifact_sha256") != manifest.get("provider_artifact_sha256")
        or composition.get("artifact") != artifact.get("provider_artifact_sha256")
        or composition.get("count") != 1
        or composition.get("secrets") != 6
        or composition.get("resource") != manifest["registrations"][0]["resource_verifier_ref"]
        or composition.get("effect") != manifest["registrations"][0]["effect_ref"]
        or composition.get("bytecode") is not True
    ):
        raise ValueError("Installed provider composition differs from secret-free pins")
    return {
        "schema_version": 1,
        "profile": "isolated_environment_provider_installation_v1",
        "provider": PROVIDER,
        "base_wheel_sha256": hashlib.sha256(wheels[0].read_bytes()).hexdigest(),
        "provider_wheel_sha256": hashlib.sha256(wheels[1].read_bytes()).hexdigest(),
        "provider_artifact_sha256": artifact["provider_artifact_sha256"],
        "registrations": composition["count"],
        "runtime_secret_purposes": composition["secrets"],
        "provider_code_imported_only_after_manifest": True,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--base-wheel", required=True)
    parser.add_argument("--provider-wheel", required=True)
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args(argv)
    try:
        result = verify(args.base_wheel, args.provider_wheel, python=args.python)
    except Exception:  # noqa: BLE001 -- temporary paths and provider diagnostics remain private
        parser.exit(1, "Isolated environment provider installation verification failed.\n")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
