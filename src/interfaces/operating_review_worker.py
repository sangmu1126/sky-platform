"""One bounded operating review pass for an external timer; no cloud provisioning."""

import json
import os
from datetime import UTC, datetime

from adapters.state.operating_review_lock import PostgresOperatingReviewLocks
from adapters.state.postgres import (
    PostgresDeploymentRecordStore,
    PostgresStateSettings,
    RotatingDatabaseConnection,
)
from adapters.state.readiness import check_database_ready
from interfaces.operating_review import OperatingReviewController, load_operating_policies
from interfaces.shared_database_worker import (
    current_membership,
    load_hosted_identity,
    load_pool_configuration,
)


def run_operating_review(args, parser):
    try:
        if (
            not args.once
            or args.initialize_pool
            or args.operation_id
            or args.attempt_id
            or (args.dedicated_config and not args.enqueue_dedicated_preparation)
        ):
            raise ValueError("Operating review requires one bounded pass without mutation options")
        state = PostgresStateSettings.from_environment()
        source, _ = load_pool_configuration(args.pool_config)
        if (
            source.pool.account_id != os.environ.get("SKY_AWS_ACCOUNT_ID")
            or source.pool.region != state.region
            or source.pool.control_database == state.database
        ):
            raise ValueError("Workload/state registration mismatch")
        identity = load_hosted_identity(args)
        policies = load_operating_policies(
            args.operating_review_policy_config, account_id=source.pool.account_id, region=state.region
        )
        if args.enqueue_dedicated_preparation:
            from adapters.aws.job_queue import SqsOperationQueue
            from interfaces.dedicated_database_worker import load_dedicated_configuration

            settings = load_dedicated_configuration(args.dedicated_config, source)
            if any(policy.target_configuration_digest != settings.digest for policy in policies.values()):
                raise ValueError("Operating target differs from registered preparation capacity/network")
            url = os.environ.get("SKY_DEDICATED_DATABASE_QUEUE_URL", "")
            if url in {
                os.environ.get(name, "")
                for name in (
                    "SKY_JOB_QUEUE_URL",
                    "SKY_SHARED_DATABASE_QUEUE_URL",
                    "SKY_DATABASE_CUTOVER_QUEUE_URL",
                )
            }:
                raise ValueError("Automatic preparation requires a separate registered queue")
            SqsOperationQueue(url, region=state.region, account_id=source.pool.account_id, client=object())
        workspace = os.environ.get("SKY_STATE_WORKSPACE", "team")
        PostgresDeploymentRecordStore(None, workspace=workspace)
    except (ValueError, TypeError, KeyError, OSError):
        parser.error("Invalid operating review configuration")
    if args.check_config:
        print("Configuration valid: bounded operating review; no AWS/DB calls", flush=True)
        return
    from botocore.exceptions import BotoCoreError, ClientError

    try:
        connection = RotatingDatabaseConnection(state)
        check_database_ready(connection)
        records = PostgresDeploymentRecordStore(connection, workspace=workspace)
        controller = OperatingReviewController(records, policies)
        collect = None
        if args.collect_capacity_metrics:
            from adapters.aws.shared_database import AwsSharedDatabaseAllocator
            from adapters.database.workload_metrics import PostgresWorkloadMetrics
            from application.capacity_observation import CapacityObservationRecorder

            audited = None

            def collect(principal, job_id, policy):
                nonlocal audited
                if policy.capacity_criteria is None:
                    return
                if policy.target.account_id != source.pool.account_id:
                    raise ValueError("Foreign target")
                binding = controller.service.writer.snapshot(principal, job_id).record.get(
                    "workload_database_binding", {}
                )
                if (
                    binding.get("instance_id") != source.pool.instance_id
                    or binding.get("account_id") != source.pool.account_id
                    or binding.get("region") != source.pool.region
                ):
                    raise ValueError("Workload binding differs from audited pool")
                # Lazy: no workload client, audit or Secret read until the
                # controller has checked a current actor, consent and budget.
                if audited is None:
                    audit = AwsSharedDatabaseAllocator(source)
                    endpoint = audit._audit()
                    user, password = audit._admin_credentials(endpoint[2])
                    audited = audit, endpoint, user, password
                audit, endpoint, user, password = audited
                metrics = PostgresWorkloadMetrics(
                    lambda: audit._connection(
                        endpoint[0], endpoint[1], source.pool.control_database, user, password
                    ),
                    pool_database=source.pool.control_database,
                    collector_id=policy.capacity_criteria.collector_id,
                    clock=lambda: datetime.now(UTC).isoformat(),
                )
                CapacityObservationRecorder(controller.service, metrics).collect(principal, job_id, policy)

        coordinator = PostgresOperatingReviewLocks(connection, workspace=workspace)
        admission = None
        if args.enqueue_dedicated_preparation:
            from adapters.state.operations import PostgresOperationStore
            from application.database_promotion_workflow import PromotionPreparationAdmission

            check_database_ready(connection, operations=True)
            admission = PromotionPreparationAdmission(
                records,
                PostgresOperationStore(connection, workspace=workspace),
                policies,
                clock=lambda: datetime.now(UTC).isoformat(),
                enabled=True,
            )
        options = {"collect": collect, "coordinate": coordinator.acquire}
        if admission is not None:
            options["prepare"] = admission
        report = controller.review_automations_once(
            lambda user, org: current_membership(identity, user, org), **options
        )
        print(
            json.dumps(
                {
                    "reviews": report,
                    "preparation_admission_enabled": admission is not None,
                    "execution_enabled": False,
                }
            ),
            flush=True,
        )
    except (OSError, ValueError, BotoCoreError, ClientError):
        parser.exit(1, "Operating review unavailable; check state, membership and telemetry permissions.\n")
