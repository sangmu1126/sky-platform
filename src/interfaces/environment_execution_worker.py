"""Hosted worker for operator-pinned reviewed environment executions."""

import os
import signal
import threading
from datetime import UTC, datetime


def _reject_other_worker_options(args):
    disallowed = (
        "deploy_built_image",
        "collect_capacity_metrics",
        "pool_config",
        "enqueue_dedicated_preparation",
        "dedicated_config",
        "recovery_config",
        "recovery_user_id",
        "recovery_organization_id",
        "expected_operation_version",
        "promotion_job_id",
        "promotion_proposal_id",
        "promotion_request_key",
        "promotion_user_id",
        "promotion_organization_id",
        "operating_review_policy_config",
        "initialize_pool",
        "operation_id",
        "attempt_id",
        "operator_github_session",
        "postgres_build_config",
    )
    if any(getattr(args, name, None) not in (None, False) for name in disallowed):
        raise ValueError("Reviewed environment worker cannot include other worker options")


def run_environment_execution_worker(args, parser):
    from adapters.aws.job_queue import SqsOperationQueue
    from adapters.state.operations import PostgresOperationStore
    from adapters.state.postgres import PostgresStateSettings
    from interfaces.environment_execution_consumer import require_isolated_environment_queue
    from interfaces.environment_execution_registration import (
        environment_execution_entry_points,
        load_environment_execution_manifest,
    )
    from interfaces.shared_database_worker import load_hosted_identity

    try:
        _reject_other_worker_options(args)
        state = PostgresStateSettings.from_environment()
        account = os.environ.get("SKY_AWS_ACCOUNT_ID", "")
        workspace = os.environ.get("SKY_STATE_WORKSPACE", "team")
        PostgresOperationStore(None, workspace=workspace)
        queue_url = require_isolated_environment_queue(
            os.environ.get("SKY_ENVIRONMENT_EXECUTION_QUEUE_URL", ""),
            tuple(
                os.environ.get(name, "")
                for name in (
                    "SKY_JOB_QUEUE_URL",
                    "SKY_SHARED_DATABASE_QUEUE_URL",
                    "SKY_DEDICATED_DATABASE_QUEUE_URL",
                    "SKY_DATABASE_CUTOVER_QUEUE_URL",
                )
            ),
        )
        SqsOperationQueue(queue_url, region=state.region, account_id=account, client=object())
        identity = load_hosted_identity(args)
        manifest = load_environment_execution_manifest(args.environment_execution_config, workspace=workspace)
        # Discover metadata only. Provider code and effects are not imported in check mode.
        environment_execution_entry_points(manifest.provider)
    except Exception:  # noqa: BLE001 -- provider/config diagnostics can contain private paths
        parser.error(
            "Invalid reviewed environment worker manifest, identity, state or isolated queue configuration"
        )
    if args.check_config:
        print(
            "Reviewed environment worker configuration valid; provider code, AWS and DB were not called",
            flush=True,
        )
        return

    from adapters.state.deployment_admission import PostgresDeploymentAdmission
    from adapters.state.environment_admission import PostgresEnvironmentExecutionAdmission
    from adapters.state.postgres import RotatingDatabaseConnection
    from adapters.state.readiness import check_database_ready
    from application.environment_execution_composition import (
        RegisteredEnvironmentEffectRouter,
        RegisteredEnvironmentResourceRouter,
    )
    from application.environment_execution_consumer import ReviewedEnvironmentExecutionConsumer
    from application.environment_execution_worker import RegisteredEnvironmentExecutionWorker
    from interfaces.environment_execution_consumer import run_reviewed_environment_consumer
    from interfaces.environment_execution_registration import compose_environment_executions
    from interfaces.shared_database_worker import current_membership

    try:
        compositions = compose_environment_executions(manifest)

        def resolve_principal(user_id, organization_id):
            return current_membership(identity, user_id, organization_id)

        connection = RotatingDatabaseConnection(state)
        check_database_ready(connection, operations=True)
        operations = PostgresOperationStore(connection, workspace=workspace)
        admission = PostgresEnvironmentExecutionAdmission(
            PostgresDeploymentAdmission(operations, account_id=account, region=state.region),
            current_principal=lambda principal: resolve_principal(
                principal.user_id, principal.organization_id
            ),
        )
        admission.check_ready()
        worker = RegisteredEnvironmentExecutionWorker(
            operations,
            admission,
            {value.execution.job.id: value.execution for value in compositions},
            resolve_principal,
            RegisteredEnvironmentResourceRouter(compositions),
            RegisteredEnvironmentEffectRouter(compositions),
            owner="environment-" + manifest.digest[:32],
            clock=lambda: datetime.now(UTC),
        )
        consumer = ReviewedEnvironmentExecutionConsumer(
            operations,
            SqsOperationQueue(queue_url, region=state.region, account_id=account),
            worker,
        )
        stop = threading.Event()
        previous = {value: signal.getsignal(value) for value in (signal.SIGTERM, signal.SIGINT)}
        try:
            for value in previous:
                signal.signal(value, lambda *_: stop.set())
            result = run_reviewed_environment_consumer(
                consumer, stop, once=args.once, wait_seconds=args.interval
            )
            if args.once:
                print(f"Reviewed environment consumer: {result}", flush=True)
        finally:
            for value, handler in previous.items():
                signal.signal(value, handler)
    except Exception:  # noqa: BLE001 -- provider/driver diagnostics must remain private
        parser.exit(
            1,
            "Reviewed environment worker unavailable; inspect durable operation state and registered provider configuration.\n",
        )
