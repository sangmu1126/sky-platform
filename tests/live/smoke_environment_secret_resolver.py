"""Opt-in live AWS Secrets Manager and private-file resolver smoke."""

from __future__ import annotations

import argparse
import json
import re
import secrets
import sys
import tempfile
import time
import uuid
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parents[2]
PROVIDER_SRC = ROOT / "providers" / "aws-vm-rehearsal" / "src"
sys.path[:0] = [str(ROOT / "src"), str(PROVIDER_SRC)]

from sky_aws_vm_rehearsal.provider import _execution

from adapters.runtime.environment_secrets import (
    AwsAndPrivateEnvironmentSecretResolver,
    ControlRuntimeSecretMaterial,
    DatabaseRuntimeSecretMaterial,
    RegisteredAwsEnvironmentSecret,
    RouterTransportSecretMaterial,
    private_router_transport_registration,
)


def _error_code(error):
    return str(error.response.get("Error", {}).get("Code", ""))


def _wait_absent(client, secret_arn):
    deadline = time.monotonic() + 60
    while True:
        try:
            client.describe_secret(SecretId=secret_arn)
        except ClientError as error:
            if _error_code(error) == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise RuntimeError("Timed out confirming temporary secret retirement")
        time.sleep(2)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Create, resolve, and retire five temporary Sky runtime secrets"
    )
    parser.add_argument("--apply", action="store_true", help="Create temporary billable AWS secrets")
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile", default="default")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"\d{12}", args.account):
        parser.error("--account must be a 12-digit AWS account ID")
    if not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d+", args.region):
        parser.error("--region must be a canonical AWS region")

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    sts = session.client("sts")
    caller = sts.get_caller_identity()
    if caller.get("Account") != args.account:
        raise SystemExit("AWS account differs; no resources were created")
    print(
        json.dumps(
            {
                "account": args.account,
                "region": args.region,
                "resources": ["five temporary versioned Secrets Manager secrets"],
                "retirement": "force-delete and absence verification required",
            },
            sort_keys=True,
        ),
        flush=True,
    )
    if not args.apply:
        print("Read-only preflight complete; --apply is required to create resources", flush=True)
        return

    client = session.client("secretsmanager")
    suffix = uuid.uuid4().hex[:12]
    purposes = (
        "entrypoint_probe",
        "source_control",
        "source_database",
        "target_control",
        "target_database",
    )
    created = []
    temporary = tempfile.TemporaryDirectory(prefix="sky-live-secret-resolver-")
    private_root = Path(temporary.name)
    key = private_root / "router-private-key"
    known_hosts = private_root / "router-known-hosts"
    key.write_text("sky-live-resolver-placeholder\n")
    known_hosts.write_text(
        "[127.0.0.1]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g\n"
    )
    key.chmod(0o600)
    known_hosts.chmod(0o600)
    try:
        registrations = []
        for index, purpose in enumerate(purposes, start=1):
            value = (
                {
                    "username": "sky_transfer_" + format(index, "016x"),
                    "password": secrets.token_urlsafe(32),
                }
                if purpose.endswith("database")
                else {"token": secrets.token_urlsafe(32)}
            )
            response = client.create_secret(
                Name=f"sky/rehearsal/resolver-check-{suffix}/{purpose}",
                Description="Disposable Sky environment resolver check",
                SecretString=json.dumps(value, separators=(",", ":")),
                Tags=[
                    {"Key": "sky-application-id", "Value": "rehearsal-app"},
                    {"Key": "sky-managed", "Value": "true"},
                    {"Key": "sky-purpose", "Value": "resolver-check"},
                ],
            )
            created.append(response["ARN"])
            registrations.append(
                RegisteredAwsEnvironmentSecret(
                    purpose,
                    "live-" + purpose.replace("_", "-"),
                    response["VersionId"],
                    response["ARN"],
                    (
                        ("sky-application-id", "rehearsal-app"),
                        ("sky-managed", "true"),
                        ("sky-purpose", "resolver-check"),
                    ),
                )
            )
        execution = _execution()
        router = private_router_transport_registration("live-router-transport", key, known_hosts)
        resolver = AwsAndPrivateEnvironmentSecretResolver(
            execution_revision=execution.revision,
            account_id=args.account,
            region=args.region,
            aws_secrets=tuple(registrations),
            router_transport=router,
            sts=sts,
            secretsmanager=client,
        )
        guard_calls = 0

        def guard():
            nonlocal guard_calls
            guard_calls += 1

        for registration in registrations:
            with resolver.open(
                registration.secret_ref,
                registration.version_ref,
                execution=execution,
                purpose=registration.purpose,
                guard=guard,
            ) as material:
                expected = (
                    DatabaseRuntimeSecretMaterial
                    if registration.purpose.endswith("database")
                    else ControlRuntimeSecretMaterial
                )
                if not isinstance(material, expected) or repr(material) != expected.__name__ + "()":
                    raise RuntimeError("Live typed secret material differs")
        materialized = ()
        with resolver.open(
            router.secret_ref,
            router.version_ref,
            execution=execution,
            purpose="router_transport",
            guard=guard,
        ) as material:
            if not isinstance(material, RouterTransportSecretMaterial):
                raise TypeError("Live router material differs")
            materialized = (material.private_key, material.known_hosts)
            if not all(value.is_file() and value.stat().st_mode & 0o777 == 0o600 for value in materialized):
                raise RuntimeError("Private router copies differ")
        if any(value.exists() for value in materialized) or guard_calls != 12:
            raise RuntimeError("Resolver cleanup or guard boundary differs")
        print(
            json.dumps(
                {
                    "status": "verified",
                    "aws_secret_versions": len(registrations),
                    "private_router_files": "hash-pinned-and-cleaned",
                    "resolver_ref": resolver.reference,
                    "secret_values_logged": False,
                },
                sort_keys=True,
            ),
            flush=True,
        )
    finally:
        original_error = sys.exc_info()[1]
        cleanup_errors = []
        for secret_arn in reversed(created):
            try:
                client.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
                _wait_absent(client, secret_arn)
            except Exception as error:  # noqa: BLE001 -- retain cleanup failure types only
                cleanup_errors.append(type(error).__name__)
        temporary.cleanup()
        if cleanup_errors:
            message = "Temporary secret cleanup needs attention: " + ",".join(cleanup_errors)
            if original_error is not None:
                original_error.add_note(message)
            else:
                raise RuntimeError(message)
        if created:
            print(
                "PASS: five temporary Secrets Manager resources retired and absence confirmed",
                flush=True,
            )


if __name__ == "__main__":
    main()
