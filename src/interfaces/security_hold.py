"""Trusted CLI only: operator-selected membership is not a browser login.

Requires both OS/AWS/database access and an explicit current admin membership.
No arbitrary role flag, migrations, workload mutations or queue messages.
Only explicitly reviewed false positives may be released; real incident recovery is separate.
Observe invokes the fixed ownership-checking probe; it cannot accept user URLs or receipts.
"""

import json
import os
import re
from contextlib import contextmanager
from datetime import UTC, datetime

from adapters.state.postgres import (
    PostgresDeploymentRecordStore,
    PostgresStateSettings,
    RotatingDatabaseConnection,
)
from adapters.state.readiness import check_database_ready
from application.deployment_observation import DeploymentObservationRecorder
from application.health import check_deployment
from application.security_hold import SecurityHold, validate_hold_request, validate_release_request
from domain.access import LoginSource, Principal, Role
from interfaces.b_preparation_runtime import preparation_identity
from interfaces.shared_database_worker import current_membership
from ports.state import RecordConflict


def operator(args):
    identity = preparation_identity(args)
    if args.auth_mode == "cognito":
        matches = [
            Principal(*record, LoginSource.EXTERNAL_IDP)
            for (issuer, _), record in identity.memberships.records.items()
            if issuer == identity.settings.issuer and record[:2] == (args.user_id, args.organization_id)
        ]
        if len(matches) != 1:
            raise PermissionError("Administrator membership is missing or ambiguous")
        actor = matches[0]
    else:
        actor = current_membership(identity, args.user_id, args.organization_id)
    if actor.role is not Role.ADMIN:
        raise PermissionError("Current administrator membership required")
    return actor


def run_security_hold(args, parser):
    now = datetime.now(UTC).isoformat()
    try:
        if not re.fullmatch(r"[a-f0-9]{16}", args.job_id):
            raise ValueError("Invalid deployment identity")
        release_options = (
            args.review_ref,
            args.expected_revision,
            args.expected_boundary,
            args.confirm_false_positive,
        )
        if args.action == "release-false-positive":
            if not args.confirm_false_positive or args.reason is not None or args.confirm_hold:
                raise ValueError("Explicit false-positive review confirmation required")
            validate_release_request(
                args.incident_id, args.review_ref, args.expected_revision, args.expected_boundary, now
            )
        elif any(value is not None and value is not False for value in release_options):
            raise ValueError("Release options require the false-positive release action")
        if args.action == "place":
            if not args.confirm_hold:
                raise ValueError("Explicit hold confirmation required")
            validate_hold_request(args.incident_id, args.reason, now)
        elif args.action != "release-false-positive" and (
            args.incident_id is not None or args.reason is not None or args.confirm_hold
        ):
            raise ValueError("Observation/status cannot include hold mutation options")
        state = PostgresStateSettings.from_environment()
        workspace = os.environ.get("SKY_STATE_WORKSPACE", "team")
        PostgresDeploymentRecordStore(None, workspace=workspace)
        actor = operator(args)
    except (ValueError, TypeError, KeyError, PermissionError, OSError):
        parser.error("Invalid security hold configuration, confirmation or current administrator")
    if args.check_config:
        print("Configuration valid: security hold; no AWS/DB calls", flush=True)
        return
    from botocore.exceptions import BotoCoreError, ClientError

    try:
        factory = RotatingDatabaseConnection(state)

        @contextmanager
        def connection():
            with factory() as db:
                if args.action == "status":
                    db.execute("SET TRANSACTION READ ONLY")
                yield db

        check_database_ready(connection)
        records = PostgresDeploymentRecordStore(connection, workspace=workspace)
        service = SecurityHold(records)
        if operator(args) != actor:
            raise PermissionError("Administrator membership changed")
        if args.action == "place":
            service.place(actor, args.job_id, incident_id=args.incident_id, reason=args.reason, now=now)
        if args.action == "release-false-positive":
            service.release_false_positive(
                actor,
                args.job_id,
                incident_id=args.incident_id,
                review_ref=args.review_ref,
                expected_revision=args.expected_revision,
                expected_boundary=args.expected_boundary,
                now=now,
            )
        observation = None
        if args.action == "observe":
            observation = DeploymentObservationRecorder(
                records,
                check_deployment,
                clock=lambda: datetime.now(UTC).isoformat(),
                revalidate=lambda: operator(args),
            ).collect(actor, args.job_id)
        report = service.status(actor, args.job_id)
        if operator(args) != actor:
            raise PermissionError("Administrator membership changed")
        print(
            json.dumps(
                {
                    **report,
                    "observed_only": args.action == "status",
                    **({"health_observation": observation} if observation is not None else {}),
                    "quarantine_performed": False,
                    "credentials_revoked": False,
                }
            ),
            flush=True,
        )
    except (
        ValueError,
        TypeError,
        KeyError,
        PermissionError,
        FileNotFoundError,
        OSError,
        RecordConflict,
        BotoCoreError,
        ClientError,
    ):
        parser.exit(
            1,
            "Security hold outcome could not be confirmed. Inspect status before retrying; no automatic release is performed.\n",
        )
