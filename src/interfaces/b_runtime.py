"""Explicit B API preparation/shared DB intake, outbox and maintenance."""

import argparse
import os
import signal
import sys
import threading
from uuid import uuid4


def run_outbox(publisher, stop, *, interval=5, once=False):
    while not stop.is_set():
        report = publisher.dispatch_once(limit=1)
        print(f"Outbox confirmed={report.confirmed} deferred={report.deferred}", flush=True)
        if once or stop.wait(interval):
            return


_LEDGERS = (
    ("metadata", "sky_state.schema_versions"),
    ("operation", "sky_state.operation_schema_versions"),
    ("admission", "sky_state.admission_schema_versions"),
    ("approval", "sky_state.approval_schema_versions"),
    ("preview", "sky_state.preview_schema_versions"),
)


def schema_versions(connection_factory):
    """Read every migration ledger without DDL; a missing ledger reports no versions."""
    import psycopg

    try:
        with connection_factory() as connection:
            connection.execute("SET TRANSACTION READ ONLY")
            versions = {}
            for name, table in _LEDGERS:
                if connection.execute("SELECT to_regclass(%s)", (table,)).fetchone()[0] is None:
                    versions[name] = ()
                else:
                    # Identifiers come from the fixed ledger list above, never from input.
                    rows = connection.execute(f"SELECT version FROM {table} ORDER BY version").fetchall()
                    versions[name] = tuple(row[0] for row in rows)
            return versions
    except psycopg.Error:
        raise OSError("State database schema versions are unavailable") from None


def migration_steps(connection_factory, workspace, *, account_id, region):
    """Initializers in ledger order. Construction validates the account/region without connecting."""
    from adapters.state.deployment_admission import PostgresDeploymentAdmission
    from adapters.state.deployment_approvals import PostgresDeploymentApprovals
    from adapters.state.deployment_previews import PostgresDeploymentPreviews
    from adapters.state.operations import PostgresOperationStore

    operations = PostgresOperationStore(connection_factory, workspace=workspace)
    admission = PostgresDeploymentAdmission(operations, account_id=account_id, region=region)
    approvals = PostgresDeploymentApprovals(admission)
    previews = PostgresDeploymentPreviews(approvals)
    return (operations.records, operations, admission, approvals, previews)


def run_migrations(connection_factory, workspace, *, account_id, region):
    """Apply metadata, operation, admission, approval then preview migrations.

    Each initializer re-runs its predecessors; those find their ledger current under the
    shared advisory lock and change nothing. Each step commits separately, so a rerun
    after a failure continues from the first incomplete ledger.
    """
    steps = migration_steps(connection_factory, workspace, account_id=account_id, region=region)
    before = schema_versions(connection_factory)
    for step in steps:
        step.initialize()
    after = schema_versions(connection_factory)
    for name, _ in _LEDGERS:
        applied = [version for version in after[name] if version not in before[name]]
        current = ",".join(map(str, after[name]))
        state = "applied " + ",".join(map(str, applied)) if applied else "up to date"
        print(f"{name} schema: {state} (now {current})", flush=True)


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    modes = parser.add_subparsers(dest="mode", required=True)
    api = modes.add_parser(
        "api",
        help="PostgreSQL API; preparation/admission requires explicit opt-in",
        epilog="For an already-open local SSM database tunnel, set SKY_DATABASE_SSM_FORWARD_PORT "
        "to its local port. Keep SKY_DATABASE_HOST set to the real database hostname; "
        "certificate verification remains required. This option does not open a tunnel.",
        allow_abbrev=False,
    )
    api.add_argument("--host", default="0.0.0.0")
    api.add_argument("--port", type=int, default=8080)
    api.add_argument(
        "--auth-mode",
        choices=("alb", "local", "private-operator", "cognito"),
        default="alb",
        help="Cognito preparation requires SKY_COGNITO_AUTH_JSON, SKY_MEMBERSHIPS_JSON "
        "and an HTTPS --origin; login/TLS hosting are provisioned separately",
    )
    api.add_argument("--alb-trusts-file")
    api.add_argument("--memberships-file")
    intake = api.add_mutually_exclusive_group()
    intake.add_argument(
        "--shared-database-pool-config", help="Opt in to reviewed workload DB allocation intake"
    )
    intake.add_argument(
        "--enable-preparation",
        action="store_true",
        help="Opt in to upload/preview/approval admission; no deployment consumer",
    )
    api.add_argument(
        "--enable-sqlite-preparation", action="store_true", help="Opt in to isolated SQLite preparation jobs"
    )
    api.add_argument("--origin", help="Exact browser origin for preparation or shared database consent")
    api.add_argument(
        "--operating-review-policy-config", help="Operator-reviewed scheduled DB promotion policies"
    )
    api.add_argument(
        "--check-config", action="store_true", help="Validate shared intake without AWS/DB calls"
    )
    worker = modes.add_parser("worker", help="Outbox, build and database workers", allow_abbrev=False)
    worker.add_argument(
        "--mode",
        dest="worker_mode",
        choices=(
            "outbox",
            "build",
            "preparation-outbox",
            "prepare-sqlite",
            "shared-database",
            "shared-database-queue",
            "dedicated-database",
            "dedicated-database-queue",
            "dedicated-database-admit",
            "dedicated-database-recover",
            "dedicated-database-recovery-status",
            "operating-review",
        ),
        required=True,
        help="Select outbox publisher or build consumer; ECS deployment requires --deploy-built-image",
    )
    worker.add_argument(
        "--deploy-built-image",
        action="store_true",
        help="Opt in to verified ECS deployment after remote build",
    )
    worker.add_argument(
        "--collect-capacity-metrics",
        action="store_true",
        help="Read app-scoped workload DB capacity during an operating review",
    )
    worker.add_argument("--pool-config")
    worker.add_argument("--dedicated-config")
    worker.add_argument("--recovery-config", help="Operator-audited immutable executor profile registration")
    worker.add_argument("--recovery-user-id", help="Current administrator requesting preparation recovery")
    worker.add_argument("--recovery-organization-id")
    worker.add_argument(
        "--expected-operation-version", type=int, help="Original blocked operation CAS version"
    )
    worker.add_argument("--promotion-job-id", help="Explicit preparation admission: existing deployment ID")
    worker.add_argument(
        "--promotion-proposal-id", help="Current approved OPR identifier; never a browser plan"
    )
    worker.add_argument("--promotion-request-key", help="Stable idempotency key for this approved request")
    worker.add_argument("--promotion-user-id", help="Trusted operator-selected current requester membership")
    worker.add_argument(
        "--promotion-organization-id", help="Requester organization for preparation admission"
    )
    worker.add_argument("--operating-review-policy-config")
    worker.add_argument(
        "--initialize-pool",
        action="store_true",
        help="Explicitly initialize an audited dedicated workload pool; no app allocation or deployment",
    )
    worker.add_argument("--alb-trusts-file")
    worker.add_argument("--memberships-file")
    worker.add_argument("--operation-id")
    worker.add_argument("--attempt-id")
    worker.add_argument("--check-config", action="store_true", help="Validate settings without AWS/DB calls")
    worker.add_argument(
        "--operator-github-session",
        action="store_true",
        help="Explicit local operator dispatch; never a hosted worker credential",
    )
    worker.add_argument(
        "--postgres-build-config", help="Operator registration for one existing shared PostgreSQL deployment"
    )
    worker.add_argument(
        "--once", action="store_true", help="Process one bounded batch or queue delivery and exit"
    )
    worker.add_argument("--interval", type=int, default=5)
    migrate = modes.add_parser(
        "migrate",
        help="Apply pending PostgreSQL state migrations once and exit; safe to repeat",
        allow_abbrev=False,
    )
    migrate.add_argument(
        "--shared-database-reviews",
        action="store_true",
        help="Explicitly migrate the opt-in shared DB review schema too",
    )
    migrate.add_argument(
        "--source-build-approvals",
        action="store_true",
        help="Explicitly migrate the opt-in incident source build consent ledger",
    )
    security = modes.add_parser(
        "security-hold",
        help="Trusted administrator: record a hold, inspect it, or collect an observation",
        allow_abbrev=False,
    )
    security.add_argument(
        "action",
        choices=(
            "place",
            "status",
            "observe",
            "release-false-positive",
            "restrict-database",
            "inspect-database",
            "prepare-credentials",
            "inspect-credentials",
            "inspect-credential-executor",
            "inspect-recovery-image",
            "inspect-build-approval",
            "inspect-build-image",
            "approve-artifact-review",
            "check-artifact-review",
            "check-recovery-readiness",
            "revoke-artifact-review",
            "inspect-runtime",
            "contain-runtime",
            "inspect-runtime-containment",
            "approve-recovery",
            "execute-recovery",
            "inspect-recovery",
            "finalize-source-recovery",
            "approve-source-recovery",
            "execute-source-recovery",
            "inspect-source-recovery",
            "execute-source-build",
            "observe-source-build",
            "approve-source-build",
            "check-source-build",
            "inspect-source-build",
            "revoke-source-build",
            "approve-source-review",
            "supersede-source-review",
            "check-source-review",
            "inspect-source-review",
            "revoke-source-review",
            "verify-restricted-database",
            "retire-runtime",
            "inspect-runtime-retirement",
            "confirm-runtime-retirement",
            "fence-execution",
            "inspect-execution-fence",
            "fence-secret-access",
            "inspect-secret-access",
        ),
    )
    security.add_argument("--job-id", required=True)
    security.add_argument(
        "--user-id", required=True, help="Current operator-provisioned internal administrator"
    )
    security.add_argument("--organization-id", required=True)
    security.add_argument("--artifact-review-id", help="Exact 32-hex operator request/review identity")
    security.add_argument("--artifact-review-ref", help="Bounded reference to the separate artifact review")
    security.add_argument(
        "--artifact-review-seconds", type=int, help="Artifact review validity, maximum 900 seconds"
    )
    security.add_argument(
        "--confirm-artifact-review",
        action="store_true",
        help="Record artifact review only; never release a hold or grant execution",
    )
    security.add_argument("--confirm-artifact-review-revocation", action="store_true")
    security.add_argument("--auth-mode", choices=("cognito", "alb"), default="cognito")
    security.add_argument("--alb-trusts-file")
    security.add_argument("--memberships-file")
    security.add_argument("--incident-id")
    security.add_argument(
        "--reason", choices=("suspected_compromise", "credential_exposure", "untrusted_artifact")
    )
    security.add_argument(
        "--confirm-hold",
        action="store_true",
        help="Explicitly acknowledge promotion blocking and automation-consent revocation",
    )
    security.add_argument("--review-ref", help="Bounded reference to the operator false-positive review")
    security.add_argument("--expected-revision", type=int)
    security.add_argument("--expected-boundary")
    security.add_argument(
        "--expected-operation-id",
        help="Restriction ID for DB inspection/credential preparation; preparation ID for credential inspection; containment ID for containment inspection",
    )
    security.add_argument("--pool-config", help="Trusted server-registered workload pool configuration")
    security.add_argument(
        "--dedicated-incident-config", help="Trusted app-bound dedicated RDS incident registration"
    )
    security.add_argument(
        "--confirm-database-restriction",
        action="store_true",
        help="Acknowledge stopping this app database login and its existing sessions",
    )
    security.add_argument(
        "--confirm-false-positive",
        action="store_true",
        help="Attest operator review; this is not automated security clearance",
    )
    security.add_argument(
        "--confirm-credential-preparation",
        action="store_true",
        help="Prepare a new Secret and replace the password while LOGIN remains disabled",
    )
    security.add_argument(
        "--confirm-runtime-containment",
        action="store_true",
        help="Suspend this app automatic scaling, lower its minimum and request zero running tasks",
    )
    security.add_argument(
        "--build-approval-config",
        help="Operator-owned KMS public trust, builder pins and signed bundle; expected inputs come from DB",
    )
    security.add_argument(
        "--recovery-provenance-config", help="Operator-pinned signer policy and signed attestation files"
    )
    security.add_argument(
        "--recovery-image-config", help="Operator-owned recovery image/source pin registration"
    )
    security.add_argument(
        "--incident-secret-config", help="Trusted registration of the app Secret and workload binding"
    )
    security.add_argument(
        "--confirm-secret-access-fence",
        action="store_true",
        help="Deny recorded runtime role sessions access to this app Secret only",
    )
    security.add_argument("--recovery-runtime-config")
    security.add_argument("--recovery-source-config")
    security.add_argument("--source-recovery-id")
    security.add_argument("--source-recovery-ref")
    security.add_argument("--source-recovery-seconds", type=int)
    security.add_argument("--source-recovery-profile", choices=("stateless-http", "postgresql"))
    security.add_argument("--confirm-source-recovery-approval", action="store_true")
    security.add_argument("--confirm-source-recovery-execution", action="store_true")
    security.add_argument("--confirm-source-recovery-finalization", action="store_true")
    security.add_argument("--allow-public-source-recovery", action="store_true")
    security.add_argument("--confirm-source-build-execution", action="store_true")
    security.add_argument(
        "--operator-github-session",
        action="store_true",
        help="Explicit local operator gh session; never forwarded to user code",
    )
    security.add_argument("--source-build-approval-id")
    security.add_argument("--source-build-id")
    security.add_argument("--source-build-ref")
    security.add_argument("--source-build-seconds", type=int)
    security.add_argument("--confirm-source-build-approval", action="store_true")
    security.add_argument("--confirm-source-build-revocation", action="store_true")
    security.add_argument("--source-review-id")
    security.add_argument("--predecessor-review-id")
    security.add_argument("--confirm-source-review-supersession", action="store_true")
    security.add_argument("--source-review-ref")
    security.add_argument("--source-review-seconds", type=int)
    security.add_argument("--confirm-source-review", action="store_true")
    security.add_argument("--confirm-source-review-revocation", action="store_true")
    security.add_argument("--recovery-id")
    security.add_argument("--recovery-approval-ref")
    security.add_argument("--recovery-seconds", type=int)
    security.add_argument("--confirm-recovery-approval", action="store_true")
    security.add_argument("--confirm-recovery-execution", action="store_true")
    security.add_argument("--database-baseline-sha256")
    security.add_argument("--confirm-database-verification", action="store_true")
    security.add_argument("--confirm-runtime-retirement", action="store_true")
    security.add_argument("--confirm-execution-fence", action="store_true")
    security.add_argument("--check-config", action="store_true", help="Validate without AWS/DB access")
    args = parser.parse_args(argv)
    if args.mode == "security-hold":
        from interfaces.security_hold import run_security_hold

        run_security_hold(args, parser)
        return
    if args.mode == "migrate":
        from botocore.exceptions import BotoCoreError, ClientError
        from psycopg import Error as DatabaseError

        from adapters.state.postgres import (
            PostgresDeploymentRecordStore,
            PostgresStateSettings,
            RotatingDatabaseConnection,
        )

        try:
            settings = PostgresStateSettings.from_environment()
            workspace = os.environ.get("SKY_STATE_WORKSPACE", "team")
            account_id = os.environ.get("SKY_AWS_ACCOUNT_ID", "").strip()
            PostgresDeploymentRecordStore(None, workspace=workspace)
            migration_steps(None, workspace, account_id=account_id, region=settings.region)
        except ValueError:
            parser.error("Invalid B migration database, account or workspace configuration")
        try:
            run_migrations(
                RotatingDatabaseConnection(settings), workspace, account_id=account_id, region=settings.region
            )
            if args.source_build_approvals:
                from adapters.state.source_build_approvals import PostgresSourceBuildApprovals
                from adapters.state.source_build_execution import PostgresSourceBuildExecutions

                PostgresSourceBuildExecutions(
                    PostgresSourceBuildApprovals(
                        PostgresDeploymentRecordStore(
                            RotatingDatabaseConnection(settings), workspace=workspace
                        ),
                        revalidate=lambda: None,
                    )
                ).initialize()
                from adapters.state.operations import PostgresOperationStore
                from adapters.state.source_recovery import PostgresSourceRecovery

                PostgresSourceRecovery(
                    PostgresSourceBuildExecutions(
                        PostgresSourceBuildApprovals(
                            PostgresDeploymentRecordStore(
                                RotatingDatabaseConnection(settings), workspace=workspace
                            ),
                            revalidate=lambda: None,
                        )
                    ),
                    PostgresOperationStore(RotatingDatabaseConnection(settings), workspace=workspace),
                ).initialize()
                print("source build consent schema: up to date", flush=True)
            if args.shared_database_reviews:
                from adapters.state.operations import PostgresOperationStore
                from adapters.state.shared_database_reviews import PostgresSharedDatabaseReviews

                PostgresSharedDatabaseReviews.initialize_schema(
                    PostgresOperationStore(RotatingDatabaseConnection(settings), workspace=workspace)
                )
                print("shared database review schema: up to date", flush=True)
        except (OSError, ValueError, BotoCoreError, ClientError, DatabaseError):
            # Do not log query diagnostics, credentials or DDL.
            parser.exit(
                1, "B state migration failed; check database access, schema version and configuration.\n"
            )
        return
    if args.mode == "api":
        if args.auth_mode == "cognito":
            if not args.enable_preparation or args.shared_database_pool_config or not args.origin:
                parser.error("Cognito mode requires preparation intake and an explicit HTTPS origin")
            from urllib.parse import urlsplit

            from interfaces.b_preparation_runtime import preparation_identity

            try:
                if urlsplit(args.origin).scheme != "https":
                    raise ValueError()
                preparation_identity(args)
            except (ValueError, TypeError):
                parser.error("Cognito requires exclusive identity configuration and an HTTPS origin")
        if args.auth_mode == "private-operator":
            if not args.enable_preparation or args.shared_database_pool_config:
                parser.error("Private operator mode requires preparation intake only")
            from interfaces.b_preparation_runtime import preparation_identity

            try:
                preparation_identity(args)
            except (ValueError, TypeError):
                parser.error(
                    "Private operator requires loopback, matching origin and exclusive identity configuration"
                )
        if (
            os.environ.get("SKY_DEDICATED_PREPARATION_ENABLED", "false") != "false"
            and not args.shared_database_pool_config
        ):
            parser.error("Dedicated preparation intake requires hosted shared database API")
        if args.enable_sqlite_preparation and not args.enable_preparation:
            parser.error("--enable-sqlite-preparation requires --enable-preparation")
        if (
            "SKY_DATABASE_CUTOVER_REGISTRATIONS_JSON" in os.environ
            or os.environ.get("SKY_DATABASE_CUTOVER_ENABLED", "false") != "false"
        ) and not args.shared_database_pool_config:
            parser.error("Cutover intake requires hosted shared database API")
        if (
            args.operating_review_policy_config or "SKY_OPERATING_REVIEW_POLICIES_JSON" in os.environ
        ) and not args.shared_database_pool_config:
            parser.error("Operating reviews require hosted shared database intake")
        if args.shared_database_pool_config:
            from interfaces.shared_database_api import run_shared_database_api

            run_shared_database_api(args, parser)
            return
        if args.enable_preparation:
            if args.check_config:
                parser.error("--check-config currently requires --shared-database-pool-config")
            if args.auth_mode not in {"private-operator", "cognito"} and (
                args.auth_mode != "alb"
                or not (
                    (args.alb_trusts_file and args.memberships_file)
                    or all(name in os.environ for name in ("SKY_ALB_TRUSTS_JSON", "SKY_MEMBERSHIPS_JSON"))
                )
                or not args.origin
            ):
                parser.error(
                    "Preparation requires ALB authentication, trust/membership configuration and --origin"
                )
            from botocore.exceptions import BotoCoreError, ClientError

            from interfaces.b_preparation_runtime import run_preparation_api

            try:
                run_preparation_api(args)
            except (OSError, ValueError, TypeError, UnicodeError, BotoCoreError, ClientError):
                parser.exit(
                    1,
                    "Preparation API unavailable; check hosted authentication, schemas, S3 and database configuration.\n",
                )
            return
        if args.origin or args.check_config:
            parser.error(
                "--origin requires preparation or shared database intake; --check-config requires shared intake"
            )
        from interfaces.http.server import serve

        forwarded = [
            "--read-only-database",
            "--host",
            args.host,
            "--port",
            str(args.port),
            "--auth-mode",
            args.auth_mode,
        ]
        for name in ("alb_trusts_file", "memberships_file"):
            value = getattr(args, name)
            if value:
                forwarded.extend(["--" + name.replace("_", "-"), value])
        previous = sys.argv
        try:
            sys.argv = [previous[0], *forwarded]
            serve(product_name="Sky")
        finally:
            sys.argv = previous
        return
    if not 1 <= args.interval <= 300:
        parser.error("--interval must be between 1 and 300 seconds")
    if args.deploy_built_image and args.worker_mode != "build":
        parser.error("--deploy-built-image requires --mode build")
    if (args.operator_github_session or args.postgres_build_config) and args.worker_mode != "build":
        parser.error("Build authentication/profile options require --mode build")
    if args.postgres_build_config and (not args.deploy_built_image or not args.pool_config):
        parser.error("PostgreSQL build deployment requires --deploy-built-image and --pool-config")
    if args.worker_mode != "dedicated-database-admit" and any(
        getattr(args, name) is not None
        for name in (
            "promotion_job_id",
            "promotion_proposal_id",
            "promotion_request_key",
            "promotion_user_id",
            "promotion_organization_id",
        )
    ):
        parser.error("Promotion admission options require dedicated-database-admit mode")
    if args.worker_mode not in {"dedicated-database-recover", "dedicated-database-recovery-status"} and any(
        getattr(args, name) is not None
        for name in (
            "recovery_config",
            "recovery_user_id",
            "recovery_organization_id",
            "expected_operation_version",
        )
    ):
        parser.error("Recovery options require dedicated-database-recover mode")
    if args.recovery_config is not None and args.worker_mode != "dedicated-database-recover":
        parser.error("Recovery registration is used only for dedicated-database-recover")
    if args.worker_mode == "operating-review":
        from interfaces.operating_review_worker import run_operating_review

        run_operating_review(args, parser)
        return
    if args.collect_capacity_metrics:
        parser.error("Capacity collection requires operating review mode")
    if args.worker_mode == "dedicated-database-recovery-status":
        from interfaces.preparation_recovery_status import run_preparation_recovery_status

        run_preparation_recovery_status(args, parser)
        return
    if args.worker_mode == "dedicated-database-recover":
        from interfaces.dedicated_database_recovery import run_preparation_recovery

        run_preparation_recovery(args, parser)
        return
    if args.worker_mode in {"dedicated-database", "dedicated-database-queue", "dedicated-database-admit"}:
        from interfaces.dedicated_database_worker import run_dedicated_database

        run_dedicated_database(args, parser)
        return
    if args.dedicated_config or args.operating_review_policy_config:
        parser.error("Dedicated database options require dedicated database mode")
    if args.worker_mode in {"shared-database", "shared-database-queue"}:
        from interfaces.shared_database_worker import run_shared_database

        run_shared_database(args, parser)
        return
    if any(
        (
            args.pool_config,
            args.alb_trusts_file,
            args.memberships_file,
            args.operation_id,
            args.attempt_id,
            args.initialize_pool,
        )
    ):
        parser.error("Shared database options require --mode shared-database")
    if args.worker_mode in {"preparation-outbox", "prepare-sqlite"}:
        from botocore.exceptions import BotoCoreError, ClientError

        from interfaces.b_sqlite_runtime import run_sqlite_worker

        try:
            run_sqlite_worker(args)
        except (OSError, ValueError, TypeError, KeyError, BotoCoreError, ClientError):
            parser.exit(
                1,
                "SQLite preparation unavailable; check isolated queue, workspace, schemas and credentials.\n",
            )
        return
    if args.worker_mode == "build":
        from botocore.exceptions import BotoCoreError, ClientError

        from interfaces.b_build_runtime import run_build_consumer

        try:
            run_build_consumer(args)
        except (OSError, ValueError, TypeError, KeyError, BotoCoreError, ClientError):
            parser.exit(
                1,
                "Build consumer unavailable; check schemas, pinned builder configuration and credentials.\n",
            )
        return
    from botocore.exceptions import BotoCoreError, ClientError

    from adapters.aws.job_queue import SqsOperationQueue
    from adapters.state.operations import PostgresOperationStore
    from adapters.state.postgres import (
        PostgresStateSettings,
        RotatingDatabaseConnection,
    )
    from adapters.state.readiness import check_database_ready
    from application.outbox import OutboxPublisher

    try:
        settings = PostgresStateSettings.from_environment()
        account = os.environ.get("SKY_AWS_ACCOUNT_ID", "")
        url = os.environ.get("SKY_JOB_QUEUE_URL", "")
        # A sentinel avoids constructing a boto client during configuration validation.
        SqsOperationQueue(url, region=settings.region, account_id=account, client=object())
        allocation_url = os.environ.get("SKY_SHARED_DATABASE_QUEUE_URL", "")
        if allocation_url:
            if allocation_url == url:
                raise ValueError("Allocation queue must be separate from the build queue")
            SqsOperationQueue(allocation_url, region=settings.region, account_id=account, client=object())
        dedicated_url = os.environ.get("SKY_DEDICATED_DATABASE_QUEUE_URL", "")
        if dedicated_url:
            if dedicated_url in {url, allocation_url}:
                raise ValueError("Dedicated preparation queue must be separate")
            SqsOperationQueue(dedicated_url, region=settings.region, account_id=account, client=object())
        cutover_url = os.environ.get("SKY_DATABASE_CUTOVER_QUEUE_URL", "")
        if cutover_url:
            if cutover_url in {url, allocation_url, dedicated_url}:
                raise ValueError("Cutover queue must be separate")
            SqsOperationQueue(cutover_url, region=settings.region, account_id=account, client=object())
        workspace = os.environ.get("SKY_STATE_WORKSPACE", "team")
        PostgresOperationStore(None, workspace=workspace)
    except ValueError:
        parser.error("Invalid B worker database, workspace or queue configuration")
    if args.check_config:
        print("Configuration valid: outbox publisher only; no AWS/DB calls", flush=True)
        return
    try:
        connection = RotatingDatabaseConnection(settings)
        check_database_ready(connection, operations=True)
        store = PostgresOperationStore(connection, workspace=workspace)
        queue = SqsOperationQueue(url, region=settings.region, account_id=account)
        from application.shared_database_consumer import AllocationQueueRouter

        queue = AllocationQueueRouter(
            store,
            queue,
            SqsOperationQueue(allocation_url, region=settings.region, account_id=account)
            if allocation_url
            else None,
            promotion_queue=SqsOperationQueue(dedicated_url, region=settings.region, account_id=account)
            if dedicated_url
            else None,
            cutover_queue=SqsOperationQueue(cutover_url, region=settings.region, account_id=account)
            if cutover_url
            else None,
        )
        publisher = OutboxPublisher(store, queue, "outbox-" + uuid4().hex)
        stop = threading.Event()
        previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
        try:
            for sig in previous:
                signal.signal(sig, lambda *_: stop.set())
            run_outbox(publisher, stop, interval=args.interval, once=args.once)
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
    except (OSError, ValueError, BotoCoreError, ClientError):
        # Do not log query diagnostics, commands, credentials or queue bodies.
        parser.exit(1, "B outbox publisher unavailable; check database schema, IAM and configuration.\n")
