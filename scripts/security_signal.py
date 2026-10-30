"""Apply a signed signal through trusted operator membership; no HTTP intake.

Requires existing administrator access to Sky state and current membership.
Detector registration is an operator-controlled local file, never an uploaded app.
No public API permission or automatic release/credential/runtime mutation is added.
"""

import argparse
import base64
import json
from datetime import UTC, datetime
from pathlib import Path

from application.security_signals import RegisteredDetector, SecuritySignalIntake


def load_bounded(path, limit):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate security signal field")
            value[key] = item
        return value

    with Path(path).open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Security signal document exceeds limit")
    return json.loads(data, object_pairs_hook=unique)


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--auth-mode", choices=("cognito", "alb"), required=True)
    parser.add_argument("--alb-trusts-file")
    parser.add_argument("--memberships-file")
    parser.add_argument("--user-id", required=True)
    parser.add_argument("--organization-id", required=True)
    parser.add_argument("--detectors", required=True)
    parser.add_argument("--event", required=True)
    parser.add_argument("--confirm-hold", action="store_true", required=True)
    args = parser.parse_args()
    try:
        # Read-only collectors/build controllers reuse load_bounded without DB
        # drivers or operator credentials. Import mutation adapters only here.
        from interfaces.security_hold import operator

        actor = operator(args)
        config = load_bounded(args.detectors, 16384)
        if (
            not isinstance(config, dict)
            or set(config) != {"version", "detectors"}
            or type(config["version"]) is not int
            or config["version"] != 1
            or not isinstance(config["detectors"], list)
            or not 1 <= len(config["detectors"]) <= 16
        ):
            raise ValueError()
        registrations = []
        for item in config["detectors"]:
            if not isinstance(item, dict) or set(item) != {
                "detector_id",
                "organization_id",
                "application_id",
                "public_key",
                "reasons",
            }:
                raise ValueError()
            registrations.append(
                RegisteredDetector(
                    item["detector_id"],
                    item["organization_id"],
                    base64.b64decode(item["public_key"], validate=True),
                    frozenset(item["reasons"]),
                    item["application_id"],
                )
            )
        event = load_bounded(args.event, 4096)
        import os

        from adapters.state.postgres import (
            PostgresDeploymentRecordStore,
            PostgresStateSettings,
            RotatingDatabaseConnection,
        )

        records = PostgresDeploymentRecordStore(
            RotatingDatabaseConnection(PostgresStateSettings.from_environment()),
            workspace=os.environ.get("SKY_STATE_WORKSPACE", "team"),
        )
        # Re-read operator membership immediately before the guarded state change.
        current = operator(args)
        if current != actor:
            raise PermissionError()
        hold = SecuritySignalIntake(records, tuple(registrations)).apply(
            current, event, now=datetime.now(UTC).isoformat()
        )
    except (ValueError, TypeError, KeyError, PermissionError, FileNotFoundError, OSError):
        parser.exit(
            1, "Security signal refused or outcome uncertain; inspect existing state before retrying.\n"
        )
    print(
        json.dumps(
            {
                "status": "security_hold",
                "incident_id": hold["incident_id"],
                "runtime_recovery_executed": False,
            }
        )
    )


if __name__ == "__main__":
    main()
