"""Admin-only persisted recovery inspection; no workload registration or mutations."""

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
from application.incident_recovery_inspection import IncidentRecoveryInspection
from application.security_hold import validate_release_request
from interfaces.security_hold import operator
from ports.state import RecordConflict


def run_recovery_inspection(args, parser):
    allowed = {
        "mode",
        "action",
        "job_id",
        "user_id",
        "organization_id",
        "auth_mode",
        "alb_trusts_file",
        "memberships_file",
        "incident_id",
        "expected_revision",
        "expected_boundary",
        "recovery_id",
        "check_config",
    }
    try:
        if any(
            value is not None and value is not False
            for name, value in vars(args).items()
            if name not in allowed
        ):
            raise ValueError("Inspection cannot include mutation or workload options")
        if not re.fullmatch(r"[a-f0-9]{16}", args.job_id or "") or not re.fullmatch(
            r"[a-f0-9]{32}", args.recovery_id or ""
        ):
            raise ValueError("Exact job and recovery identities required")
        validate_release_request(
            args.incident_id,
            "recovery-inspection",
            args.expected_revision,
            args.expected_boundary,
            datetime.now(UTC).isoformat(),
        )
        settings = PostgresStateSettings.from_environment()
        workspace = os.environ.get("SKY_STATE_WORKSPACE", "team")
        PostgresDeploymentRecordStore(None, workspace=workspace)
        actor = operator(args)
    except (ValueError, TypeError, KeyError, PermissionError, OSError):
        parser.error("Invalid recovery inspection scope, options or administrator configuration")
    if args.check_config:
        print("Recovery inspection configuration valid; no AWS/DB calls")
        return
    from botocore.exceptions import BotoCoreError, ClientError
    from psycopg import Error as DatabaseError

    try:
        factory = RotatingDatabaseConnection(settings)

        @contextmanager
        def connection():
            with factory() as db:
                db.execute("SET TRANSACTION READ ONLY")
                yield db

        check_database_ready(connection)
        service = IncidentRecoveryInspection(
            PostgresDeploymentRecordStore(connection, workspace=workspace),
            clock=lambda: datetime.now(UTC).isoformat(),
            revalidate=lambda: operator(args),
        )
        report = service.inspect(
            actor,
            args.job_id,
            recovery_id=args.recovery_id,
            incident_id=args.incident_id,
            expected_boundary=args.expected_boundary,
            expected_revision=args.expected_revision,
        )
        print(json.dumps({"incident_recovery_inspection": report}, sort_keys=True))
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        PermissionError,
        FileNotFoundError,
        RecordConflict,
        BotoCoreError,
        ClientError,
        DatabaseError,
    ):
        parser.exit(
            1, "Recovery metadata inspection unavailable; no activation, retry or state change requested.\n"
        )
