"""Trusted administrator finalization of a previously submitted deployment."""

import argparse
import json
import os
from uuid import UUID


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--user-id", required=True)
    parser.add_argument("--organization-id", required=True)
    parser.add_argument("--auth-mode", choices=("alb", "cognito"), default="alb")
    parser.add_argument("--alb-trusts-file")
    parser.add_argument("--memberships-file")
    parser.add_argument("--pool-config")
    parser.add_argument("--postgres-build-config")
    parser.add_argument("--operator-github-session", action="store_true")
    parser.add_argument("--confirm-original-executor-stopped", action="store_true")
    parser.add_argument("--check-config", action="store_true")
    args = parser.parse_args(argv)
    try:
        from adapters.aws.build_image import EcrBuildVerifier
        from adapters.aws.built_deployment import BuiltImageDeployment
        from adapters.github.remote_build import GitHubApi, GitHubRemoteBuild, InstallationToken
        from adapters.state.build_execution import PostgresBuildExecutionStore
        from adapters.state.postgres import PostgresStateSettings, RotatingDatabaseConnection
        from adapters.state.readiness import check_database_ready
        from application.build_reconciliation import BuildDeploymentReconciliation
        from interfaces.postgres_build import load_postgres_build_configuration
        from interfaces.security_hold import operator
        from ports.remote_builds import BuildSettings

        if (
            str(UUID(args.operation_id)) != args.operation_id
            or args.expected_version < 1
            or bool(args.pool_config) != bool(args.postgres_build_config)
            or (not args.check_config and not args.confirm_original_executor_stopped)
        ):
            raise ValueError(
                "Explicit existing operation, version and stopped executor confirmation required"
            )
        if args.operator_github_session:
            if os.environ.get("ECS_CONTAINER_METADATA_URI_V4") or os.environ.get(
                "ECS_CONTAINER_METADATA_URI"
            ):
                raise ValueError("Local operator GitHub sessions are unavailable in hosted tasks")
            from adapters.github.operator_session import OperatorGitHubSession

            token = OperatorGitHubSession()
        else:
            token = InstallationToken(
                os.environ.get("SKY_GITHUB_APP_ID", ""),
                os.environ.get("SKY_GITHUB_INSTALLATION_ID", ""),
                os.environ.get("SKY_GITHUB_APP_PRIVATE_KEY", ""),
                os.environ.get("SKY_BUILDER_REPOSITORY", ""),
            )
        settings = BuildSettings.from_environment(os.environ)
        database = PostgresStateSettings.from_environment()
        actor = operator(args)
        profile = (
            load_postgres_build_configuration(
                args.postgres_build_config, args.pool_config, settings, check_only=args.check_config
            )
            if args.postgres_build_config
            else None
        )
        if args.check_config:
            print("Configuration valid: deployment observation/finalization only; no AWS/DB/GitHub calls")
            return
        connection = RotatingDatabaseConnection(database)
        check_database_ready(connection, operations=True)
        store = PostgresBuildExecutionStore(
            connection, workspace=os.environ.get("SKY_STATE_WORKSPACE", "team")
        )
        service = BuildDeploymentReconciliation(
            store,
            GitHubRemoteBuild(settings, GitHubApi(token)),
            EcrBuildVerifier(settings),
            BuiltImageDeployment(settings, database_profile=profile),
            settings,
            revalidate=lambda: operator(args),
        )
        result = service.observe(
            actor,
            args.operation_id,
            expected_version=args.expected_version,
            executor_stopped=args.confirm_original_executor_stopped,
        )
        print(json.dumps(result), flush=True)
    except Exception:  # noqa: BLE001 -- SDK/SQL/token diagnostics must not reach CLI output
        parser.exit(
            1,
            "Deployment reconciliation unavailable; inspect the exact durable operation without resubmission.\n",
        )
