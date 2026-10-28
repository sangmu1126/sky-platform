"""Collect one read-only registered CloudTrail observation for operator review.

No automatic hold, release, notification, credential revocation or cloud change.
Schedule only under a dedicated read-only role; output is private local evidence.
"""

import argparse
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from adapters.aws.security_monitor import CloudTrailSecretAccessMonitor, SecretAccessRegistration
from scripts.security_signal import load_bounded


def collect(registration_file, *, now, session=None):
    raw = load_bounded(registration_file, 8192)
    if (
        not isinstance(raw, dict)
        or set(raw) != {"account_id", "region", "role_arn", "role_id", "forbidden_secrets"}
        or not isinstance(raw["forbidden_secrets"], list)
    ):
        raise ValueError("Exact registered detector scope required")
    registration = SecretAccessRegistration(**{**raw, "forbidden_secrets": tuple(raw["forbidden_secrets"])})
    observation = CloudTrailSecretAccessMonitor(registration, session=session).observe(now=now)
    return {
        "version": 1,
        "registration_digest": hashlib.sha256(
            json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "observation": observation,
        "operator_review_required": True,
        "cloud_changed": False,
        "security_hold_changed": False,
    }


def write_private(path, report):
    data = (json.dumps(report, indent=2, allow_nan=False) + "\n").encode()
    if len(data) > 65536:
        raise ValueError("Bounded security observation required")
    # Caller chooses an operator-owned directory. Never replace historical
    # evidence or follow a final-component link supplied by a workload.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        Path(path).unlink(missing_ok=True)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--registration", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = collect(args.registration, now=datetime.now(UTC).isoformat())
        write_private(args.output, report)
    except Exception:  # noqa: BLE001 -- never expose provider diagnostics or identifiers in CLI errors
        parser.exit(
            1, "Security observation unavailable; no safety or recovery conclusion may be inferred.\n"
        )
    print(
        json.dumps({"status": "observation_saved", "operator_review_required": True, "cloud_changed": False})
    )


if __name__ == "__main__":
    main()
