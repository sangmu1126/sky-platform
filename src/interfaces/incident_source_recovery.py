"""Explicit trusted-operator new-source recovery; never automatic hold release."""

import json
import os
import re
from contextlib import contextmanager
from copy import copy
from datetime import UTC, datetime

from adapters.aws.build_objects import S3BuildObjects
from adapters.aws.source_artifacts import S3ArtifactSettings
from adapters.aws.source_build_image import EcrSourceBuildVerifier
from adapters.github.remote_build import GitHubApi, GitHubRemoteBuild, InstallationToken
from adapters.state.operations import PostgresOperationStore
from adapters.state.postgres import PostgresStateSettings, RotatingDatabaseConnection
from adapters.state.readiness import check_database_ready
from adapters.state.source_build_approvals import PostgresSourceBuildApprovals
from adapters.state.source_build_execution import PostgresSourceBuildExecutions
from adapters.state.source_recovery import PostgresSourceRecovery
from application.incident_source_build import IncidentSourceBuildApproval
from application.incident_source_build_execution import IncidentSourceBuildExecution
from application.incident_source_recovery import IncidentSourceRecovery
from application.incident_source_review import IncidentSourceReview
from application.security_hold import validate_release_request
from interfaces.security_hold import operator
from ports.remote_builds import BuildSettings
from ports.state import RecordConflict


def run_source_recovery(args, parser):
    approve = args.action == "approve-source-recovery"
    execute = args.action == "execute-source-recovery"
    finalize = args.action == "finalize-source-recovery"
    external = approve or execute or finalize
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
        "source_build_approval_id",
        "source_recovery_id",
        "source_recovery_ref",
        "source_recovery_seconds",
        "source_recovery_profile",
        "confirm_source_recovery_approval",
        "confirm_source_recovery_execution",
        "confirm_source_recovery_finalization",
        "allow_public_source_recovery",
        "operator_github_session",
        "pool_config",
        "dedicated_incident_config",
        "incident_secret_config",
        "recovery_runtime_config",
    }
    try:
        if any(v is not None and v is not False for k, v in vars(args).items() if k not in allowed):
            raise ValueError("Disjoint source recovery options required")
        if (
            args.confirm_source_recovery_approval is not approve
            or args.confirm_source_recovery_execution is not execute
            or args.confirm_source_recovery_finalization is not finalize
        ):
            raise ValueError("Distinct explicit recovery confirmation required")
        for value, length in [
            (args.job_id, 16),
            (args.source_build_approval_id, 32),
            (args.source_recovery_id, 32),
        ]:
            if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{" + str(length) + "}", value):
                raise ValueError("Exact source recovery identity required")
        if bool(args.source_recovery_ref) != approve or (
            not approve and (args.source_recovery_seconds is not None or args.allow_public_source_recovery)
        ):
            raise ValueError("Execution cannot change recovery approval inputs")
        seconds = args.source_recovery_seconds if args.source_recovery_seconds is not None else 900
        if type(seconds) is not int or not 1 <= seconds <= 900:
            raise ValueError("Bounded recovery approval lifetime required")
        validate_release_request(
            args.incident_id,
            args.source_recovery_ref or "source-recovery-read",
            args.expected_revision,
            args.expected_boundary,
            datetime.now(UTC).isoformat(),
        )
        state = PostgresStateSettings.from_environment()
        actor = operator(args)
        workspace = os.environ.get("SKY_STATE_WORKSPACE", "team")
        PostgresOperationStore(None, workspace=workspace)
        profile = args.source_recovery_profile or "stateless-http"
        token = None
        settings = None
        configuration = None
        runtime_registration = None
        if external:
            settings = BuildSettings.from_environment(os.environ)
            if (settings.account_id, settings.region) != (state.secret_arn.split(":")[4], state.region):
                raise ValueError("Builder and registered state account differ")
            if args.operator_github_session:
                from adapters.github.operator_session import OperatorGitHubSession

                token = OperatorGitHubSession()
            else:
                token = InstallationToken(
                    os.environ.get("SKY_GITHUB_APP_ID", ""),
                    os.environ.get("SKY_GITHUB_INSTALLATION_ID", ""),
                    os.environ.get("SKY_GITHUB_APP_PRIVATE_KEY", ""),
                    settings.repository,
                )
            if profile == "postgresql":
                from interfaces.incident_recovery import load_runtime_registration
                from interfaces.recovery_readiness import load_readiness_configuration

                configuration = load_readiness_configuration(args, state)
                runtime_registration = load_runtime_registration(args.recovery_runtime_config)
                if (
                    configuration[0] is None
                    or configuration[2] is None
                    or (
                        runtime_registration.account_id,
                        runtime_registration.region,
                        runtime_registration.job_id,
                        runtime_registration.organization_id,
                        runtime_registration.recovery_id,
                    )
                    != (
                        settings.account_id,
                        settings.region,
                        args.job_id,
                        actor.organization_id,
                        args.source_recovery_id,
                    )
                ):
                    raise ValueError("Exact separate workload and recovery registration required")
            elif any(
                [
                    args.pool_config,
                    args.dedicated_incident_config,
                    args.incident_secret_config,
                    args.recovery_runtime_config,
                ]
            ):
                raise ValueError("Stateless path cannot ignore workload registration")
        elif (
            args.operator_github_session
            or args.source_recovery_profile
            or any(
                [
                    args.pool_config,
                    args.dedicated_incident_config,
                    args.incident_secret_config,
                    args.recovery_runtime_config,
                ]
            )
        ):
            raise ValueError("Inspection needs no provider credentials or configuration")
    except (OSError, ValueError, TypeError, KeyError, PermissionError):
        parser.error("Invalid source recovery scope, profile, pins, confirmation or administrator")
    if args.check_config:
        print("Source recovery configuration valid; no AWS/DB/GitHub calls")
        return
    from botocore.exceptions import BotoCoreError, ClientError
    from psycopg import Error as DatabaseError

    try:
        factory = RotatingDatabaseConnection(state)

        @contextmanager
        def connection():
            with factory() as db:
                if not external:
                    db.execute("SET TRANSACTION READ ONLY")
                yield db

        check_database_ready(connection, operations=True)
        operations = PostgresOperationStore(connection, workspace=workspace)
        records = operations.records
        clock = lambda: datetime.now(UTC).isoformat()

        def reviewer(user):
            selected = copy(args)
            selected.user_id = user
            return operator(selected)

        ledger = PostgresSourceBuildApprovals(records, revalidate=lambda: operator(args))
        ledger.check_ready()
        executions = PostgresSourceBuildExecutions(ledger)
        reviews = IncidentSourceReview(
            records, None, clock=clock, revalidate=lambda: operator(args), reviewer=reviewer
        )
        consents = IncidentSourceBuildApproval(reviews, ledger, settings, clock=clock, reviewer=reviewer)
        build_execution = IncidentSourceBuildExecution(
            consents,
            executions,
            None,
            GitHubRemoteBuild(settings, GitHubApi(token)) if external else None,
            S3BuildObjects(S3ArtifactSettings(settings.bucket, settings.region, settings.account_id))
            if external
            else None,
            EcrSourceBuildVerifier(settings) if external else None,
            clock=clock,
        )
        runtime = None
        prerequisites = None
        retirement = None
        if external:
            if profile == "postgresql":
                from adapters.aws.incident_recovery import AwsIncidentRecovery
                from adapters.aws.source_recovery import PostgreSQLSourceRecovery
                from interfaces.incident_verification import compose_verification

                prerequisites, verification, _ = compose_verification(
                    args, state, configuration, operations, actor, clock=clock
                )
                runtime = PostgreSQLSourceRecovery(
                    AwsIncidentRecovery(runtime_registration, verification, clock=clock)
                )
            else:
                from adapters.aws.built_deployment import BuiltImageDeployment
                from adapters.aws.source_recovery import StatelessSourceRecovery
                from adapters.state.incident_execution import PostgresIncidentExecutionControl
                from interfaces.incident_verification import runtime_retirement

                runtime = StatelessSourceRecovery(BuiltImageDeployment(settings))
                if records.load_job(args.job_id).record.get("result") is not None:
                    retirement = runtime_retirement(
                        records,
                        PostgresIncidentExecutionControl(operations, revalidate=lambda: operator(args)),
                        actor,
                        args.job_id,
                        clock=clock,
                        revalidate=lambda: operator(args),
                    )
        service = IncidentSourceRecovery(
            build_execution,
            PostgresSourceRecovery(executions, operations),
            runtime,
            clock=clock,
            profile=profile,
            prerequisites=prerequisites,
            retirement=retirement,
        )
        options = {
            "approval_id": args.source_build_approval_id,
            "recovery_id": args.source_recovery_id,
            "incident_id": args.incident_id,
            "expected_boundary": args.expected_boundary,
            "expected_revision": args.expected_revision,
        }
        if approve:
            report = service.approve(
                actor,
                args.job_id,
                review_ref=args.source_recovery_ref,
                seconds=seconds,
                public_access=args.allow_public_source_recovery,
                **options,
            )
        elif execute:
            report = service.execute(actor, args.job_id, **options)
        elif finalize:
            report = service.finalize(actor, args.job_id, **options)
        else:
            report = service.inspect(actor, args.job_id, **options)
        print(json.dumps({"incident_source_recovery": report}, sort_keys=True))
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        PermissionError,
        RecordConflict,
        BotoCoreError,
        ClientError,
        DatabaseError,
    ):
        parser.exit(
            1,
            "Source recovery outcome requires inspection; never automatically replay activation or stop a possibly committed runtime.\n",
        )
