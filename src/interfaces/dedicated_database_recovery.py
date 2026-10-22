"""Explicit operator-only preparation reconciliation; no HTTP or automatic activation."""

import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from adapters.aws.dedicated_database import AwsDedicatedDatabasePreparer
from adapters.aws.preparation_executor_observation import EcsStoppedPreparationObserver
from adapters.state.operations import PostgresOperationStore
from adapters.state.postgres import (
    PostgresDeploymentRecordStore,
    PostgresStateSettings,
    RotatingDatabaseConnection,
)
from adapters.state.readiness import check_database_ready
from application.available_target_preparation_recovery import AvailableTargetPreparationRecoveryAuthority
from application.database_preparation_recovery import PromotionPreparationRecovery
from application.database_promotion_workflow import KIND
from application.deployment_writes import DeploymentMetadataWriter
from domain.access import Role
from interfaces.dedicated_database_worker import load_dedicated_configuration
from interfaces.operating_review import load_operating_policies
from interfaces.shared_database_worker import (
    current_membership,
    load_hosted_identity,
    load_pool_configuration,
)
from ports.preparation_executor import CreateOnlyPreparationProfile
from ports.state import RecordConflict


@dataclass(frozen=True)
class PreparationRecoveryRegistration:
    cluster_arn: str
    profile: CreateOnlyPreparationProfile
    lifetime_seconds: int


def load_recovery_registration(path, *, account_id, region):
    raw = os.environ.get("SKY_PREPARATION_RECOVERY_JSON")
    if raw is not None:
        if path:
            raise ValueError("Use recovery registration file or environment, not both")
        data = raw.encode()
    elif path:
        with Path(path).open("rb") as stream:
            data = stream.read(16385)
    else:
        raise ValueError("Explicit audited recovery registration required")
    if len(data) > 16384:
        raise ValueError("Recovery registration exceeds size bound")

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate recovery registration field")
            value[key] = item
        return value

    value = json.loads(data, object_pairs_hook=unique)
    if (
        not isinstance(value, dict)
        or set(value) != {"version", "cluster_arn", "profile", "lifetime_seconds"}
        or type(value["version"]) is not int
        or value["version"] != 1
        or not isinstance(value["profile"], dict)
        or set(value["profile"]) != {"profile_id", "task_definition_arn", "images"}
        or value["profile"]["profile_id"] != "dedicated-rds-create-only-v1"
        or not isinstance(value["profile"]["images"], dict)
        or type(value["lifetime_seconds"]) is not int
        or not 1 <= value["lifetime_seconds"] <= 300
    ):
        raise ValueError("Invalid recovery registration")
    profile = CreateOnlyPreparationProfile(
        value["profile"]["task_definition_arn"], tuple(sorted(value["profile"]["images"].items()))
    )
    prefix = f"arn:aws:ecs:{region}:{account_id}:"
    if (
        not isinstance(value["cluster_arn"], str)
        or not re.fullmatch(re.escape(prefix) + r"cluster/[A-Za-z0-9_-]{1,255}", value["cluster_arn"])
        or not profile.task_definition_arn.startswith(prefix + "task-definition/")
    ):
        raise ValueError("Recovery registration account or region mismatch")
    return PreparationRecoveryRegistration(value["cluster_arn"], profile, value["lifetime_seconds"])


def run_preparation_recovery(args, parser):
    try:
        if not args.once or args.initialize_pool:
            raise ValueError("Recovery must be a single explicit operation")
        if (
            any(
                not isinstance(value, str) or str(UUID(value)) != value
                for value in (args.operation_id, args.attempt_id)
            )
            or type(args.expected_operation_version) is not int
            or not 1 <= args.expected_operation_version < 9223372036854775807
            or any(
                not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", value)
                for value in (args.recovery_user_id, args.recovery_organization_id)
            )
        ):
            raise ValueError("Original operation, attempt, version and administrator required")
        state = PostgresStateSettings.from_environment()
        source, _ = load_pool_configuration(args.pool_config)
        if (
            source.pool.account_id != os.environ.get("SKY_AWS_ACCOUNT_ID")
            or source.pool.region != state.region
            or source.pool.control_database == state.database
        ):
            raise ValueError("Workload pool and state registration mismatch")
        settings = load_dedicated_configuration(args.dedicated_config, source)
        policies = load_operating_policies(
            args.operating_review_policy_config, account_id=source.pool.account_id, region=state.region
        )
        if not policies or any(
            policy.target_configuration_digest != settings.digest
            or policy.cost_quote is None
            or not (policy.isolation_required or policy.capacity_criteria is not None)
            for policy in policies.values()
        ):
            raise ValueError("Costed reviewed policies must match the dedicated registration")
        registration = load_recovery_registration(
            args.recovery_config, account_id=source.pool.account_id, region=state.region
        )
        workspace = os.environ.get("SKY_STATE_WORKSPACE", "team")
        PostgresOperationStore(None, workspace=workspace)

        def resolve(user, organization):
            # Re-read operator-owned identity files during long observations.
            if (
                load_recovery_registration(
                    args.recovery_config, account_id=source.pool.account_id, region=state.region
                )
                != registration
                or load_operating_policies(
                    args.operating_review_policy_config,
                    account_id=source.pool.account_id,
                    region=state.region,
                )
                != policies
            ):
                raise RecordConflict("Recovery registration or policy changed during observation")
            return current_membership(load_hosted_identity(args), user, organization)

        operator = resolve(args.recovery_user_id, args.recovery_organization_id)
        if operator.role is not Role.ADMIN:
            raise PermissionError("Current organization administrator required")
    except (ValueError, TypeError, KeyError, PermissionError, OSError):
        parser.error("Invalid preparation recovery registration, operation or administrator")
    if args.check_config:
        print("Configuration valid: explicit preparation recovery; no AWS/DB calls", flush=True)
        return
    from botocore.exceptions import BotoCoreError, ClientError

    try:
        connection = RotatingDatabaseConnection(state)
        check_database_ready(connection, operations=True)
        records = PostgresDeploymentRecordStore(connection, workspace=workspace)
        operations = PostgresOperationStore(connection, workspace=workspace)
        operation = operations.get(args.operation_id)
        if (
            operation.kind != KIND
            or operation.status != "needs_attention"
            or operation.attempt_id != args.attempt_id
            or operation.row_version != args.expected_operation_version
        ):
            raise RecordConflict("Original blocked operation snapshot required")
        binding = (
            DeploymentMetadataWriter(records)
            .snapshot(operator, operation.command.get("job_id"))
            .record.get("workload_database_binding", {})
        )
        if (
            not isinstance(binding, dict)
            or binding.get("role") != "shared_workload"
            or (binding.get("account_id"), binding.get("region"), binding.get("instance_id"))
            != (source.pool.account_id, source.pool.region, source.pool.instance_id)
        ):
            raise ValueError("Original source differs from registered workload pool")
        target = AwsDedicatedDatabasePreparer(settings)
        stopped = EcsStoppedPreparationObserver(
            registration.cluster_arn, workspace=workspace, profile=registration.profile
        )
        authority = AvailableTargetPreparationRecoveryAuthority(
            operations, stopped, target, lifetime=registration.lifetime_seconds
        )
        service = PromotionPreparationRecovery(
            records,
            operations,
            policies,
            target,
            resolve,
            authority,
            clock=lambda: datetime.now(UTC).isoformat(),
        )
        result = service.resume(operator, operation.id, args.attempt_id, args.expected_operation_version)
        print(json.dumps({**result, "delivery": "durable_outbox"}), flush=True)
    except (ValueError, TypeError, KeyError, PermissionError, OSError, BotoCoreError, ClientError):
        parser.exit(1, "Preparation recovery unavailable; inspect the original durable operation.\n")
