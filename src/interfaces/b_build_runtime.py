"""Opt-in build/deployment consumer; task protection required; no Docker or runtime migrations."""

import os
import signal
import threading
from uuid import uuid4


def run_build_consumer(args):
    from adapters.aws.build_image import EcrBuildVerifier
    from adapters.aws.build_objects import S3BuildObjects
    from adapters.aws.job_queue import SqsOperationQueue
    from adapters.aws.source_artifacts import S3ArtifactSettings
    from adapters.aws.task_protection import EcsTaskProtection
    from adapters.github.remote_build import (
        GitHubApi,
        GitHubRemoteBuild,
        InstallationToken,
    )
    from adapters.state.build_execution import PostgresBuildExecutionStore
    from adapters.state.deployment_admission import PostgresDeploymentAdmission
    from adapters.state.deployment_approvals import PostgresDeploymentApprovals
    from adapters.state.postgres import (
        PostgresStateSettings,
        RotatingDatabaseConnection,
    )
    from application.build_consumer import BuildConsumer
    from ports.remote_builds import BuildSettings

    database = PostgresStateSettings.from_environment()
    settings = BuildSettings.from_environment(os.environ)
    workspace = os.environ.get("SKY_STATE_WORKSPACE", "team")
    queue_url = os.environ.get("SKY_JOB_QUEUE_URL", "")
    SqsOperationQueue(queue_url, region=settings.region, account_id=settings.account_id, client=object())
    PostgresBuildExecutionStore(None, workspace=workspace)
    hosted = bool(
        os.environ.get("ECS_CONTAINER_METADATA_URI_V4") or os.environ.get("ECS_CONTAINER_METADATA_URI")
    )
    require_signatures = os.environ.get("SKY_REQUIRE_SIGNED_BUILDS", "true" if hosted else "false")
    if require_signatures not in {"true", "false"} or (hosted and require_signatures != "true"):
        raise ValueError("Hosted build consumers require signed expected input bindings")
    identity = None
    if require_signatures == "true":
        from adapters.aws.build_trust import load_build_trust

        identity = load_build_trust(
            os.environ.get("SKY_BUILD_SIGNING_TRUST_JSON"),
            account_id=settings.account_id,
            region=settings.region,
        )
    local_operator = getattr(args, "operator_github_session", False)
    if local_operator and (
        os.environ.get("ECS_CONTAINER_METADATA_URI_V4") or os.environ.get("ECS_CONTAINER_METADATA_URI")
    ):
        raise ValueError("Operator GitHub sessions cannot be used by hosted workers")
    if local_operator:

        class LocalProcessProtection:
            """No ECS task exists; the DB lease and SQS visibility still apply."""

            def set(self, enabled):
                if type(enabled) is not bool:
                    raise ValueError("Explicit local process state required")

        protection = LocalProcessProtection()
    else:
        protection = EcsTaskProtection()
    if getattr(args, "operator_github_session", False):
        from adapters.github.operator_session import OperatorGitHubSession

        token = OperatorGitHubSession()
    else:
        token = InstallationToken(
            os.environ.get("SKY_GITHUB_APP_ID", ""),
            os.environ.get("SKY_GITHUB_INSTALLATION_ID", ""),
            os.environ.get("SKY_GITHUB_APP_PRIVATE_KEY", ""),
            settings.repository,
        )
    database_profile = None
    if getattr(args, "postgres_build_config", None):
        from interfaces.postgres_build import load_postgres_build_configuration

        database_profile = load_postgres_build_configuration(
            args.postgres_build_config, args.pool_config, settings, check_only=args.check_config
        )
    if args.check_config:
        print("Build consumer configuration valid; no AWS/DB/GitHub calls", flush=True)
        return
    connection = RotatingDatabaseConnection(database)
    store = PostgresBuildExecutionStore(connection, workspace=workspace)
    PostgresDeploymentApprovals(
        PostgresDeploymentAdmission(store, account_id=settings.account_id, region=settings.region)
    ).check_ready()
    artifacts = S3ArtifactSettings(settings.bucket, settings.region, settings.account_id)
    from adapters.aws.built_deployment import BuiltImageDeployment

    deployer = (
        BuiltImageDeployment(settings, database_profile=database_profile)
        if getattr(args, "deploy_built_image", False)
        else None
    )
    database_preparer = None
    if os.environ.get("SKY_DATABASE_BUILD_POLICY_JSON") is not None:
        if not hosted or database_profile is not None or deployer is None:
            raise ValueError("Automatic database preparation requires one hosted scoped deployment consumer")
        from interfaces.hosted_database_build import load_hosted_database_build

        database_preparer = load_hosted_database_build(settings)
    if deployer is not None and hosted:
        from adapters.aws.deployment_session import DeploymentRoleRegistration, ScopedDeploymentFactory

        deployer = ScopedDeploymentFactory(
            settings,
            DeploymentRoleRegistration.load(os.environ.get("SKY_DEPLOYMENT_ROLE_JSON")),
            database_profile=database_profile,
            database_resolver=database_preparer,
        )
    objects = S3BuildObjects(artifacts)
    verifier = EcrBuildVerifier(settings)
    if identity is not None:
        from adapters.aws.build_image import SignedEcrBuildVerifier
        from adapters.aws.kms_build_key import AwsKmsBuildKeyObserver

        verifier = SignedEcrBuildVerifier(
            settings,
            objects=objects,
            identity=identity,
            key_observer=AwsKmsBuildKeyObserver(identity),
            require_inspection=hosted,
        )
    from adapters.aws.build_execution_grant import S3BuildExecutionGrants

    consumer = BuildConsumer(
        store,
        SqsOperationQueue(queue_url, region=settings.region, account_id=settings.account_id),
        GitHubRemoteBuild(settings, GitHubApi(token)),
        objects,
        verifier,
        settings,
        protection,
        "build-" + uuid4().hex,
        deployer=deployer,
        database_preparer=database_preparer,
        execution_grants=S3BuildExecutionGrants(
            artifacts, authorization=lambda request, lease: store.build_delegation(lease, request, settings)
        ),
    )
    stop = threading.Event()
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        for sig in previous:
            signal.signal(sig, lambda *_: stop.set())
        while not stop.is_set():
            report = consumer.consume_once(stop)
            print("Build consumer: " + report, flush=True)
            if args.once or stop.wait(args.interval):
                break
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
