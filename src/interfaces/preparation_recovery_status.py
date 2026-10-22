"""Read-only operator inspection after an ambiguous preparation recovery response."""

import json
import os
import re
from contextlib import contextmanager
from uuid import UUID

from adapters.state.operations import PostgresOperationStore
from adapters.state.postgres import (
    PostgresDeploymentRecordStore,
    PostgresStateSettings,
    RotatingDatabaseConnection,
)
from adapters.state.readiness import check_database_ready
from application.database_promotion_workflow import KIND
from application.deployment_writes import DeploymentMetadataWriter
from domain.access import Role
from interfaces.database_preparation import DatabasePreparationController
from interfaces.shared_database_worker import current_membership, load_hosted_identity


def recovery_status(
    records, operations, principal, operation_id, *, original_attempt=None, original_version=None
):
    operation = operations.get(operation_id)
    record = DeploymentMetadataWriter(records).snapshot(principal, operation.command.get("job_id")).record
    if (
        principal.role is not Role.ADMIN
        or operation.kind != KIND
        or operation.application_id != record.get("application_id")
        or operation.command.get("requested_by", {}).get("organization_id") != principal.organization_id
    ):
        raise FileNotFoundError("Owned preparation operation not found")
    value = DatabasePreparationController._receipt(operation, operation.command["job_id"])
    if value["status"] not in {"queued", "running", "succeeded", "failed", "needs_attention"}:
        raise ValueError("Unknown preparation state")
    confirmation = "not_requested"
    if original_attempt is not None:
        receipt = operation.external_receipt or {}
        resolution = receipt.get("resolution", {})
        if (
            isinstance(resolution, dict)
            and resolution.get("outcome") == "resume"
            and resolution.get("attempt_id") == original_attempt
            and type(resolution.get("row_version")) is int
            and resolution["row_version"] == original_version
        ):
            confirmation = "recorded"
        elif (
            operation.status == "needs_attention"
            and operation.attempt_id == original_attempt
            and operation.row_version == original_version
        ):
            confirmation = "not_recorded_at_snapshot"
        else:
            confirmation = "unconfirmed"
    return {
        **value,
        "attempt_id": operation.attempt_id,
        "row_version": operation.row_version,
        "original_recovery_request": confirmation,
        "observed_only": True,
    }


def run_preparation_recovery_status(args, parser):
    try:
        if (
            not args.once
            or args.initialize_pool
            or any(
                value is not None
                for value in (args.pool_config, args.dedicated_config, args.operating_review_policy_config)
            )
        ):
            raise ValueError("Status is one read-only inspection without provisioning settings")
        if (
            not isinstance(args.operation_id, str)
            or str(UUID(args.operation_id)) != args.operation_id
            or any(
                not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", value)
                for value in (args.recovery_user_id, args.recovery_organization_id)
            )
        ):
            raise ValueError("Operation and current operator required")
        supplied = args.attempt_id is not None or args.expected_operation_version is not None
        if supplied and (
            not isinstance(args.attempt_id, str)
            or str(UUID(args.attempt_id)) != args.attempt_id
            or type(args.expected_operation_version) is not int
            or not 1 <= args.expected_operation_version < 9223372036854775807
        ):
            raise ValueError("Original attempt and version must be supplied together")
        state = PostgresStateSettings.from_environment()
        workspace = os.environ.get("SKY_STATE_WORKSPACE", "team")
        PostgresOperationStore(None, workspace=workspace)
        operator = current_membership(
            load_hosted_identity(args), args.recovery_user_id, args.recovery_organization_id
        )
        if operator.role is not Role.ADMIN:
            raise PermissionError("Current administrator required")
    except (ValueError, TypeError, KeyError, PermissionError, OSError):
        parser.error("Invalid preparation status configuration or operator")
    if args.check_config:
        print("Configuration valid: preparation recovery status; no AWS/DB calls", flush=True)
        return
    from botocore.exceptions import BotoCoreError, ClientError

    try:
        factory = RotatingDatabaseConnection(state)

        @contextmanager
        def read_only():
            with factory() as connection:
                connection.execute("SET TRANSACTION READ ONLY")
                yield connection

        check_database_ready(read_only, operations=True)
        records = PostgresDeploymentRecordStore(read_only, workspace=workspace)
        operations = PostgresOperationStore(read_only, workspace=workspace)
        value = recovery_status(
            records,
            operations,
            operator,
            args.operation_id,
            original_attempt=args.attempt_id,
            original_version=args.expected_operation_version,
        )
        # Re-read operator-controlled membership files before printing identities.
        if (
            current_membership(load_hosted_identity(args), operator.user_id, operator.organization_id)
            != operator
        ):
            raise PermissionError("Operator membership changed during inspection")
        print(json.dumps(value), flush=True)
    except (ValueError, TypeError, KeyError, PermissionError, OSError, BotoCoreError, ClientError):
        parser.exit(1, "Preparation status unavailable; no recovery action was performed.\n")
