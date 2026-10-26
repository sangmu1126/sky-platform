"""Trusted operator operation barrier, separate from normal queue execution."""

import json
import os
import re
from datetime import UTC, datetime

from adapters.state.incident_execution import PostgresIncidentExecutionControl
from adapters.state.operations import PostgresOperationStore
from adapters.state.postgres import PostgresStateSettings, RotatingDatabaseConnection
from adapters.state.readiness import check_database_ready
from application.security_hold import validate_release_request
from interfaces.security_hold import operator
from ports.state import RecordConflict


def run_execution_control(args, parser):
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
        "check_config",
        "confirm_execution_fence",
        "confirm_runtime_retirement",
    }
    try:
        if any(value not in (None, False) for name, value in vars(args).items() if name not in allowed):
            raise ValueError("Execution control cannot include other action options")
        if args.confirm_execution_fence != (args.action == "fence-execution"):
            raise ValueError("Disjoint explicit execution barrier confirmation required")
        if args.confirm_runtime_retirement != (
            args.action in {"retire-runtime", "confirm-runtime-retirement"}
        ):
            raise ValueError("Explicit retirement or reconciliation confirmation required")
        validate_release_request(
            args.incident_id,
            "execution-fence",
            args.expected_revision,
            args.expected_boundary,
            datetime.now(UTC).isoformat(),
        )
        state = PostgresStateSettings.from_environment()
        if not re.fullmatch(r"[a-f0-9]{16}", args.job_id):
            raise ValueError("Exact job identity required")
        actor = operator(args)
        workspace = os.environ.get("SKY_STATE_WORKSPACE", "team")
        PostgresOperationStore(None, workspace=workspace).records._identity(args.job_id)
    except (ValueError, PermissionError):
        parser.error("Invalid operation fence scope, confirmation or administrator configuration")
    if args.check_config:
        print("Execution barrier configuration valid; no AWS/DB calls")
        return
    try:
        connection = RotatingDatabaseConnection(state)
        check_database_ready(connection, operations=True)
        operations = PostgresOperationStore(connection, workspace=workspace)
        service = PostgresIncidentExecutionControl(operations, revalidate=lambda: operator(args))
        options = {
            "incident_id": args.incident_id,
            "expected_boundary": args.expected_boundary,
            "expected_revision": args.expected_revision,
        }
        if args.action in {"fence-execution", "inspect-execution-fence"}:
            action = service.fence if args.action == "fence-execution" else service.inspect
            report = action(actor, args.job_id, **options)
        else:
            import boto3
            from botocore.config import Config

            from adapters.aws.incident_runtime_retirement import AwsIncidentRuntimeRetirement
            from application.deployment_writes import DeploymentMetadataWriter
            from application.incident_runtime_retirement import IncidentRuntimeRetirement
            from domain.incident_runtime import runtime_identity

            snapshot = DeploymentMetadataWriter(operations.records).snapshot(actor, args.job_id)
            _, region, *_ = runtime_identity(snapshot.record.get("result"))
            session = boto3.Session(region_name=region)
            config = Config(retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=10)
            native = AwsIncidentRuntimeRetirement(
                client=session.client("ecs", config=config),
                sts=session.client("sts", config=config),
                backend="ecs_standard"
                if snapshot.record["result"]["target"] == "aws-ecs-standard"
                else "ecs_express",
            )
            retirement = IncidentRuntimeRetirement(
                operations.records,
                service,
                native,
                clock=lambda: datetime.now(UTC).isoformat(),
                revalidate=lambda: operator(args),
            )
            if args.action == "retire-runtime":
                report = retirement.retire(actor, args.job_id, **options)
            else:
                report = retirement.inspect(
                    actor, args.job_id, confirm=args.action == "confirm-runtime-retirement", **options
                )
        print(json.dumps({"execution_control": report}, sort_keys=True))
    except (OSError, ValueError, PermissionError, FileNotFoundError, RecordConflict):
        parser.exit(
            1, "Execution barrier unavailable; inspect persisted state before retrying any mutation.\n"
        )
