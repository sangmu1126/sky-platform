"""Periodically collect exact AWS observations and persist signed review proposals.

No user code, model call, automatic release, notification to people, or workload
mutation. Operator consumes a proposal with scripts.security_signal after review.
Registration/key/output paths are operator-owned, never uploaded app parameters.
"""

import argparse
import base64
import json
import os
import stat
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from adapters.aws.security_audit import S3SecurityAudit
from adapters.aws.security_monitor import CloudTrailSecretAccessMonitor, SecretAccessRegistration
from application.security_observations import SecurityObservationRouter
from application.security_signals import RegisteredDetector


def write_private(path, report):
    data = (json.dumps(report, indent=2, allow_nan=False) + "\n").encode()
    if len(data) > 65536:
        raise ValueError("Bounded security observation required")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def document(raw):
    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("Duplicate collector registration field")
            result[name] = value
        return result

    if len(raw) > 16384:
        raise ValueError("Bounded collector registration required")
    return json.loads(raw, object_pairs_hook=unique)


def load_bounded(path, limit):
    with Path(path).open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Bounded collector registration required")
    return document(raw)


def private_file(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise ValueError("Operator-private configuration/key required")
        raw = source.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Private file exceeds bound")
    return raw


def collect_cycle(configuration, key, output, *, session, now, persist=write_private):
    if (
        not isinstance(configuration, dict)
        or set(configuration)
        not in (
            {"version", "expires_at", "aws", "detector", "scope", "audit"},
            {"version", "expires_at", "aws", "detector", "scope", "audit", "review_queue_url"},
        )
        or type(configuration["version"]) is not int
        or configuration["version"] != 1
    ):
        raise ValueError("Exact operator collector registration required")
    stamp, expiry = datetime.fromisoformat(now), datetime.fromisoformat(configuration["expires_at"])
    if stamp.tzinfo is None or expiry.tzinfo is None or stamp >= expiry:
        raise ValueError("Collector registration expired")
    raw = configuration["aws"]
    registration = SecretAccessRegistration(**{**raw, "forbidden_secrets": tuple(raw["forbidden_secrets"])})
    detector = RegisteredDetector(
        **{
            **configuration["detector"],
            "public_key": base64.b64decode(configuration["detector"]["public_key"], validate=True),
            "reasons": frozenset(configuration["detector"]["reasons"]),
        }
    )
    audit_settings = configuration["audit"]
    if set(audit_settings) != {"bucket", "role_arn"} or not audit_settings["role_arn"].startswith(
        f"arn:aws:iam::{registration.account_id}:role/sky-"
    ):
        raise ValueError("Same-account audit writer role required")
    # Deliberately separate audit credentials: the collector cannot replace the
    # registered key with an app-supplied credential or share its own broad keys.
    credentials = session.client("sts", region_name=registration.region).assume_role(
        RoleArn=audit_settings["role_arn"],
        RoleSessionName="sky-security-audit-" + uuid4().hex[:12],
        DurationSeconds=900,
    )["Credentials"]
    import boto3

    writer_session = boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )
    audit = S3SecurityAudit(
        bucket=audit_settings["bucket"],
        account_id=registration.account_id,
        region=registration.region,
        organization_id=detector.organization_id,
        application_id=detector.application_id,
        session=writer_session,
    )
    router = SecurityObservationRouter(detector, key, audit.append, scope=configuration["scope"])
    result = router.collect_secrets(CloudTrailSecretAccessMonitor(registration, session=session), now=now)
    destination = output / ("cycle-" + uuid4().hex + ".json")
    persist(destination, {"version": 1, "collected_at": now, **result})
    notifications = 0
    notifier = None
    if configuration.get("review_queue_url"):
        from adapters.aws.security_review_queue import SecurityReviewQueue

        notifier = SecurityReviewQueue(
            configuration["review_queue_url"],
            account_id=registration.account_id,
            region=registration.region,
            session=session,
        )
    for item in result["observations"]:
        if notifier is not None:
            notifier.notify(item)
            notifications += 1
        if item["signed_hold_proposal"] is not None:
            persist(
                output / ("signal-" + item["event"]["event_id"] + "-" + uuid4().hex[:8] + ".json"),
                item["signed_hold_proposal"],
            )
    return {
        "status": "review_recorded",
        "notifications_queued": notifications,
        "findings": len(result["observations"]),
        "collection_complete": result["collection_complete"],
        "automatic_release_permitted": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--registration", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--cycles", type=int, default=1)
    args = parser.parse_args(argv)
    try:
        if not 60 <= args.interval <= 900 or not 1 <= args.cycles <= 60:
            raise ValueError("Bounded collection schedule required")
        # Registration is re-read each cycle so expiry or operator replacement
        # takes effect. Do not infer authorization from provider login origin.
        key = load_pem_private_key(private_file(args.private_key, 4096), password=None)
        args.output_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = args.output_directory.stat()
        if args.output_directory.is_symlink() or info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise ValueError("Operator-private review directory required")
        import boto3

        session = boto3.Session()
        for index in range(args.cycles):
            private_file(args.registration, 16384)
            configuration = load_bounded(args.registration, 16384)
            print(
                json.dumps(
                    collect_cycle(
                        configuration,
                        key,
                        args.output_directory,
                        session=session,
                        now=datetime.now(UTC).isoformat(),
                    )
                ),
                flush=True,
            )
            if index + 1 < args.cycles:
                time.sleep(args.interval)
    except Exception:  # noqa: BLE001 -- avoid provider/credential/source diagnostics in console
        parser.exit(
            1, "Security collection incomplete; inspect private evidence. No security clearance inferred.\n"
        )


def hosted_main():
    """Trusted ECS observer; no DB access, user code, persistent key file or release."""
    import re
    import signal
    import threading

    import boto3

    stop = threading.Event()
    previous = {name: signal.getsignal(name) for name in (signal.SIGINT, signal.SIGTERM)}
    for name in previous:
        signal.signal(name, lambda *_: stop.set())
    try:
        if not os.environ.get("ECS_CONTAINER_METADATA_URI_V4"):
            raise ValueError("Hosted collector needs its registered ECS task identity")
        registration = document(os.environ["SKY_SECURITY_REGISTRATION_JSON"])
        expected = os.environ["SKY_SECURITY_COLLECTOR_TASK_ROLE_ARN"]
        account = registration["aws"]["account_id"]
        if not re.fullmatch(r"arn:aws:iam::" + account + r":role/sky-[a-z0-9-]+", expected):
            raise ValueError("Exact same-account collector role required")
        key_bytes = os.environ["SKY_SECURITY_SIGNING_PRIVATE_KEY"].encode()
        if len(key_bytes) > 4096:
            raise ValueError("Bounded signing key required")
        key = load_pem_private_key(key_bytes, password=None)
        del key_bytes
        session = boto3.Session(region_name=registration["aws"]["region"])
        identity = session.client("sts").get_caller_identity()
        if not identity.get("Arn", "").startswith(
            "arn:aws:sts::" + account + ":assumed-role/" + expected.rsplit("/", 1)[1] + "/"
        ):
            raise ValueError("Collector runtime identity differs from registration")
        for _ in range(60):
            if stop.is_set():
                break
            now = datetime.now(UTC).isoformat()
            if datetime.fromisoformat(now) >= datetime.fromisoformat(registration["expires_at"]):
                print(json.dumps({"status": "registration_expired", "security_clearance": False}), flush=True)
                stop.wait(900)
                continue
            # Audit is durable in the independent S3 sink; proposals are carried
            # in the encrypted review queue. The observer needs no writable mount.
            result = collect_cycle(
                registration, key, Path("/unused"), session=session, now=now, persist=lambda *_: None
            )
            print(json.dumps({"collected_at": now, **result, "security_clearance": False}), flush=True)
            if stop.wait(60):
                break
    except Exception:  # noqa: BLE001 -- never print provider/credential diagnostics
        print(json.dumps({"status": "collection_incomplete", "security_clearance": False}), flush=True)
        raise SystemExit(1) from None
    finally:
        for name, handler in previous.items():
            signal.signal(name, handler)


if __name__ == "__main__":
    main()
