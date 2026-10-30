"""Opt-in hosted preparation runtime, no legacy App or startup schema writes."""

import os
from http.server import ThreadingHTTPServer
from pathlib import Path

from adapters.aws.source_artifacts import S3ArtifactSettings, S3SourceArtifactStore
from adapters.state.deployment_admission import PostgresDeploymentAdmission
from adapters.state.deployment_approvals import PostgresDeploymentApprovals
from adapters.state.deployment_previews import PostgresDeploymentPreviews
from adapters.state.deployment_reads import PostgresDeploymentReads
from adapters.state.operations import PostgresOperationStore
from adapters.state.postgres import PostgresStateSettings, RotatingDatabaseConnection
from application.deployment_preparation import DeploymentPreparationService
from application.deployment_reads import DeploymentReadService
from application.source_artifacts import SourceArtifactService
from interfaces.http.alb_identity import AlbRequestAuthenticator
from interfaces.http.deployment_approvals import DatabaseApprovalApp
from interfaces.http.deployment_preparation import DatabasePreparationApp, handler_for_preparation


def preparation_identity(args):
    """Accept exactly one complete identity source, matching the read-only API."""
    private = os.environ.get("SKY_PRIVATE_OPERATOR_JSON")
    cognito = os.environ.get("SKY_COGNITO_AUTH_JSON")
    if getattr(args, "auth_mode", "alb") == "cognito":
        from interfaces.http.cognito_identity import CognitoRequestAuthenticator

        if (
            private is not None
            or args.alb_trusts_file
            or args.memberships_file
            or "SKY_ALB_TRUSTS_JSON" in os.environ
        ):
            raise ValueError("Cognito and other identity configuration cannot be mixed")
        return CognitoRequestAuthenticator.from_json(cognito, os.environ.get("SKY_MEMBERSHIPS_JSON"))
    if cognito is not None:
        raise ValueError("Cognito configuration requires explicit cognito mode")
    if getattr(args, "auth_mode", "alb") == "private-operator":
        from interfaces.http.private_operator import PrivateOperatorAuthenticator

        if (
            args.alb_trusts_file
            or args.memberships_file
            or "SKY_ALB_TRUSTS_JSON" in os.environ
            or "SKY_MEMBERSHIPS_JSON" in os.environ
        ):
            raise ValueError("Private operator and ALB identity configuration cannot be mixed")
        return PrivateOperatorAuthenticator.from_json(
            private, host=args.host, port=args.port, origin=args.origin
        )
    if private is not None:
        raise ValueError("Private operator configuration requires explicit private-operator mode")
    trusts = os.environ.get("SKY_ALB_TRUSTS_JSON")
    members = os.environ.get("SKY_MEMBERSHIPS_JSON")
    has_environment = trusts is not None or members is not None
    has_files = bool(args.alb_trusts_file or args.memberships_file)
    if has_environment:
        if has_files or trusts is None or members is None:
            raise ValueError("Use one complete ALB identity configuration source")
        return AlbRequestAuthenticator.from_json(trusts, members)
    if not args.alb_trusts_file or not args.memberships_file:
        raise ValueError("Both ALB identity files are required")
    return AlbRequestAuthenticator.from_files(Path(args.alb_trusts_file), Path(args.memberships_file))


def run_preparation_api(args):
    authenticator = preparation_identity(args)
    # Validate browser origin before constructing credential or AWS providers.
    DatabaseApprovalApp(None, None, authenticator=authenticator, origin=args.origin, readiness=lambda: None)
    browser = None
    login_domain = os.environ.get("SKY_COGNITO_LOGIN_DOMAIN")
    if login_domain is not None:
        if args.auth_mode != "cognito":
            raise ValueError("Managed browser login requires explicit Cognito mode")
        from interfaces.http.cognito_browser import CognitoBrowser

        browser = CognitoBrowser(login_domain, args.origin, authenticator.settings)
    database = PostgresStateSettings.from_environment()
    artifacts = S3ArtifactSettings.from_environment()
    workspace = os.environ.get("SKY_STATE_WORKSPACE", "team")
    sqlite_workspace = None
    if getattr(args, "enable_sqlite_preparation", False):
        from interfaces.b_sqlite_runtime import preparation_scope

        sqlite_workspace, _ = preparation_scope(os.environ, artifacts)
    operations = PostgresOperationStore(None, workspace=workspace)
    connection = RotatingDatabaseConnection(database)
    operations = PostgresOperationStore(connection, workspace=operations.workspace)
    approvals = PostgresDeploymentApprovals(
        PostgresDeploymentAdmission(operations, account_id=artifacts.account_id, region=artifacts.region)
    )
    previews = PostgresDeploymentPreviews(approvals)
    previews.check_ready()
    sources = SourceArtifactService(S3SourceArtifactStore(artifacts))
    database_policy = None
    if os.environ.get("SKY_DATABASE_BUILD_POLICY_JSON"):
        from application.database_build_policy import DatabaseBuildPolicy

        database_policy = DatabaseBuildPolicy.load(os.environ["SKY_DATABASE_BUILD_POLICY_JSON"])
        if (database_policy.account_id, database_policy.region) != (artifacts.account_id, artifacts.region):
            raise ValueError("Database build policy differs from the hosted destination")
    preparation = DeploymentPreparationService(sources, previews, database_policy=database_policy)
    reads = DeploymentReadService(PostgresDeploymentReads(connection, workspace=workspace))
    sqlite_jobs = None
    if sqlite_workspace is not None:
        from application.sqlite_preparation_jobs import SqlitePreparationJobs

        sqlite_jobs = SqlitePreparationJobs(
            previews, PostgresOperationStore(connection, workspace=sqlite_workspace)
        )
    app = DatabasePreparationApp(
        reads,
        approvals,
        preparation,
        authenticator=authenticator,
        origin=args.origin,
        workspace=workspace,
        sqlite_jobs=sqlite_jobs,
    )
    app.cognito_browser = browser
    from interfaces.operating_lifecycle import compose_operating_lifecycle

    pool_settings = None
    if "SKY_SHARED_DATABASE_POOL_JSON" in os.environ:
        from interfaces.shared_database_worker import load_pool_configuration

        pool_settings, _ = load_pool_configuration(None)
        if (
            pool_settings.pool.account_id != artifacts.account_id
            or pool_settings.pool.region != database.region
            or pool_settings.pool.control_database == database.database
        ):
            raise ValueError("Separate workload pool registration required")
    handler = compose_operating_lifecycle(
        app,
        handler_for_preparation(app),
        connection,
        operations,
        account_id=artifacts.account_id,
        region=database.region,
        policy_path=getattr(args, "operating_review_policy_config", None),
        pool_settings=pool_settings,
    )
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(
        f"Sky preparation API: http://{args.host}:{args.port}/prepare; deployment consumer is not included",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
