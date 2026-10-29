"""Explicit administrator assessment; never derive DB trust from source or login origin."""

import argparse
import json
import os
from datetime import UTC, datetime

from adapters.state.postgres import (
    PostgresDeploymentRecordStore,
    PostgresStateSettings,
    RotatingDatabaseConnection,
)
from application.database_security_review import review_database_security
from interfaces.security_hold import operator
from scripts.security_signal import load_bounded


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--auth-mode", choices=("cognito", "alb"), required=True)
    parser.add_argument("--alb-trusts-file")
    parser.add_argument("--memberships-file")
    parser.add_argument("--user-id", required=True)
    parser.add_argument("--organization-id", required=True)
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--expected-revision", type=int, required=True)
    parser.add_argument("--assessment", required=True)
    parser.add_argument("--review-ref", required=True)
    parser.add_argument("--seconds", type=int, default=3600)
    parser.add_argument("--confirm-trust-review", action="store_true", required=True)
    args = parser.parse_args(argv)
    try:
        actor = operator(args)
        assessment = load_bounded(args.assessment, 2048)
        records = PostgresDeploymentRecordStore(
            RotatingDatabaseConnection(PostgresStateSettings.from_environment()),
            workspace=os.environ.get("SKY_STATE_WORKSPACE", "team"),
        )
        current = operator(args)
        if current != actor:
            raise PermissionError("Membership changed")
        result = review_database_security(
            records,
            current,
            args.job_id,
            assessment,
            expected_revision=args.expected_revision,
            review_ref=args.review_ref,
            now=datetime.now(UTC).isoformat(),
            seconds=args.seconds,
        )
    except Exception:  # noqa: BLE001 -- no provider/source diagnostics in console
        parser.exit(1, "Database isolation review refused or uncertain; inspect the current record.\n")
    print(
        json.dumps(
            {
                "status": "database_security_review_recorded",
                "expires_at": result["expires_at"],
                "database_created": False,
                "security_clearance": False,
            }
        )
    )


if __name__ == "__main__":
    main()
