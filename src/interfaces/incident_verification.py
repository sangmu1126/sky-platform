"""Explicit trusted-operator authentication probes on a retired workload only."""

import json
import os
import re
from datetime import UTC, datetime

from adapters.state.incident_execution import PostgresIncidentExecutionControl
from adapters.state.operations import PostgresOperationStore
from adapters.state.postgres import PostgresStateSettings, RotatingDatabaseConnection
from adapters.state.readiness import check_database_ready
from application.deployment_writes import DeploymentMetadataWriter
from application.incident_database_verification import IncidentDatabaseVerification
from application.security_hold import validate_release_request
from domain.database import DatabaseBinding
from interfaces.recovery_readiness import load_readiness_configuration
from interfaces.security_hold import operator
from ports.state import RecordConflict


def runtime_retirement(records, control, principal, job_id, *, clock, revalidate):
    import boto3
    from botocore.config import Config

    from adapters.aws.incident_runtime_retirement import AwsIncidentRuntimeRetirement
    from application.incident_runtime_retirement import IncidentRuntimeRetirement
    from domain.incident_runtime import runtime_identity

    snapshot = DeploymentMetadataWriter(records).snapshot(principal, job_id)
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
    return IncidentRuntimeRetirement(records, control, native, clock=clock, revalidate=revalidate)


def run_database_verification(args, parser):
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
        "pool_config",
        "dedicated_incident_config",
        "incident_secret_config",
        "database_baseline_sha256",
        "confirm_database_verification",
    }
    try:
        if any(value not in (None, False) for name, value in vars(args).items() if name not in allowed):
            raise ValueError("Database verification cannot include other mutation options")
        if (
            not args.confirm_database_verification
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", args.database_baseline_sha256 or "")
            or not re.fullmatch(r"[a-f0-9]{16}", args.job_id)
        ):
            raise ValueError("Explicit bounded baseline and verification confirmation required")
        validate_release_request(
            args.incident_id,
            "database-verification",
            args.expected_revision,
            args.expected_boundary,
            datetime.now(UTC).isoformat(),
        )
        state = PostgresStateSettings.from_environment()
        pool, dedicated, registration = load_readiness_configuration(args, state)
        if pool is None or registration is None:
            raise ValueError("Registered workload pool and exact Secret required")
        actor = operator(args)
        workspace = os.environ.get("SKY_STATE_WORKSPACE", "team")
        PostgresOperationStore(None, workspace=workspace)
    except (OSError, ValueError, PermissionError, TypeError):
        parser.error("Invalid registered database verification baseline, identity or scope")
    if args.check_config:
        print("Database verification configuration valid; no AWS/DB calls")
        return
    try:
        from adapters.aws.dedicated_incident import AwsDedicatedIncidentDatabase
        from adapters.aws.shared_database import AwsSharedDatabaseAllocator

        connection = RotatingDatabaseConnection(state)
        check_database_ready(connection, operations=True)
        operations = PostgresOperationStore(connection, workspace=workspace)
        records = operations.records
        snapshot = DeploymentMetadataWriter(records).snapshot(actor, args.job_id)
        binding = DatabaseBinding(**snapshot.record["workload_database_binding"])
        if binding != registration.binding:
            raise ValueError("Secret registration differs from workload binding")

        def membership():
            if operator(args) != actor:
                raise PermissionError("Current administrator membership changed")

        def unchanged():
            membership()
            if DeploymentMetadataWriter(records).snapshot(actor, args.job_id) != snapshot:
                raise RecordConflict("Workload changed during verifier construction")

        if binding.role == "dedicated_workload" and dedicated is not None and dedicated.binding == binding:
            provider = AwsDedicatedIncidentDatabase(dedicated)
        elif binding.role == "shared_workload" and dedicated is None:
            provider = AwsSharedDatabaseAllocator(pool)
        else:
            raise ValueError("Exact registered workload verification provider required")
        adapter = provider.incident_verification(
            binding, state, registration, guard=unchanged, connection_guard=membership
        )
        control = PostgresIncidentExecutionControl(operations, revalidate=lambda: operator(args))
        clock = lambda: datetime.now(UTC).isoformat()
        retired = runtime_retirement(
            records, control, actor, args.job_id, clock=clock, revalidate=lambda: operator(args)
        )
        service = IncidentDatabaseVerification(
            records, control, retired, registration, adapter, clock=clock, revalidate=lambda: operator(args)
        )
        report = service.verify(
            actor,
            args.job_id,
            incident_id=args.incident_id,
            expected_boundary=args.expected_boundary,
            expected_revision=args.expected_revision,
            expected_fingerprint=args.database_baseline_sha256,
        )
        print(json.dumps({"database_verification": report}, sort_keys=True))
    except (OSError, ValueError, PermissionError, FileNotFoundError, RecordConflict, KeyError):
        parser.exit(
            1,
            "Database verification incomplete; inspect the held workload and its login restriction before proceeding.\n",
        )


def compose_verification(args, state, configuration, operations, actor, *, clock):
    from adapters.aws.dedicated_incident import AwsDedicatedIncidentDatabase
    from adapters.aws.shared_database import AwsSharedDatabaseAllocator

    pool, dedicated, registration = configuration
    records = operations.records
    snapshot = DeploymentMetadataWriter(records).snapshot(actor, args.job_id)
    binding = DatabaseBinding(**snapshot.record["workload_database_binding"])
    if binding != registration.binding:
        raise ValueError("Secret registration differs from workload binding")

    def membership():
        if operator(args) != actor:
            raise PermissionError("Current administrator membership changed")

    def unchanged():
        membership()
        if DeploymentMetadataWriter(records).snapshot(actor, args.job_id) != snapshot:
            raise RecordConflict("Workload changed during verifier construction")

    if binding.role == "dedicated_workload" and dedicated is not None and dedicated.binding == binding:
        provider = AwsDedicatedIncidentDatabase(dedicated)
    elif binding.role == "shared_workload" and dedicated is None:
        provider = AwsSharedDatabaseAllocator(pool)
    else:
        raise ValueError("Exact registered workload verification provider required")
    adapter = provider.incident_verification(
        binding, state, registration, guard=unchanged, connection_guard=membership
    )
    control = PostgresIncidentExecutionControl(operations, revalidate=lambda: operator(args))
    retired = runtime_retirement(
        records, control, actor, args.job_id, clock=clock, revalidate=lambda: operator(args)
    )
    service = IncidentDatabaseVerification(
        records, control, retired, registration, adapter, clock=clock, revalidate=lambda: operator(args)
    )
    return service, adapter, control
