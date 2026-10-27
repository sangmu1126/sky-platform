"""Operator-only source build consent; no dispatch, build credentials or execution."""

import json
import os
import re
from contextlib import contextmanager
from copy import copy
from datetime import UTC, datetime

from adapters.aws.source_artifacts import S3ArtifactSettings, S3SourceArtifactStore
from adapters.state.postgres import (
    PostgresDeploymentRecordStore,
    PostgresStateSettings,
    RotatingDatabaseConnection,
)
from adapters.state.readiness import check_database_ready
from adapters.state.source_build_approvals import PostgresSourceBuildApprovals
from application.incident_source_build import IncidentSourceBuildApproval
from application.incident_source_review import IncidentSourceReview
from application.security_hold import validate_release_request
from application.source_artifacts import SourceArtifactService
from interfaces.security_hold import operator
from ports.remote_builds import BuildSettings, identity
from ports.state import RecordConflict


def run_source_build(args, parser):
    approve = args.action == "approve-source-build"
    revoke = args.action == "revoke-source-build"
    verify = approve or args.action == "check-source-build"
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
        "source_build_id",
        "source_build_ref",
        "source_build_seconds",
        "confirm_source_build_approval",
        "confirm_source_build_revocation",
    }
    if approve:
        allowed.add("source_review_id")
    try:
        if any(v is not None and v is not False for k, v in vars(args).items() if k not in allowed):
            raise ValueError("Disjoint source build options required")
        if (
            args.confirm_source_build_approval is not approve
            or args.confirm_source_build_revocation is not revoke
        ):
            raise ValueError("Separate explicit build consent required")
        for value, length in [(args.job_id, 16), (args.source_build_approval_id, 32)]:
            if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{" + str(length) + "}", value):
                raise ValueError("Exact build consent identity required")
        if bool(args.source_build_ref) != (approve or revoke):
            raise ValueError("Action-specific consent reference required")
        if approve:
            identity(args.source_build_id)
            if not re.fullmatch(r"[a-f0-9]{32}", args.source_review_id or ""):
                raise ValueError("Exact reviewed source required")
        elif args.source_build_id is not None or args.source_build_seconds is not None:
            raise ValueError("Build identity and lifetime require approval action")
        seconds = args.source_build_seconds if args.source_build_seconds is not None else 900
        if type(seconds) is not int or not 1 <= seconds <= 900:
            raise ValueError("Bounded build consent lifetime required")
        validate_release_request(
            args.incident_id,
            args.source_build_ref or "source-build-read",
            args.expected_revision,
            args.expected_boundary,
            datetime.now(UTC).isoformat(),
        )
        state = PostgresStateSettings.from_environment()
        workspace = os.environ.get("SKY_STATE_WORKSPACE", "team")
        PostgresDeploymentRecordStore(None, workspace=workspace)
        actor = operator(args)
        if verify:
            storage = S3ArtifactSettings.from_environment()
            settings = BuildSettings.from_environment(os.environ)
            if (storage.account_id, storage.region, storage.bucket) != (
                settings.account_id,
                settings.region,
                settings.bucket,
            ) or (settings.account_id, settings.region) != (state.secret_arn.split(":")[4], state.region):
                raise ValueError("State/source/builder registration must share account and region")
        else:
            settings = None
    except (OSError, ValueError, TypeError, KeyError, PermissionError, AttributeError):
        parser.error("Invalid source build scope, pins, confirmation or administrator")
    if args.check_config:
        print("Source build consent configuration valid; no AWS/DB calls")
        return
    from botocore.exceptions import BotoCoreError, ClientError
    from psycopg import Error as DatabaseError

    try:
        factory = RotatingDatabaseConnection(state)

        @contextmanager
        def connection():
            with factory() as db:
                if not approve and not revoke:
                    db.execute("SET TRANSACTION READ ONLY")
                yield db

        check_database_ready(connection)
        records = PostgresDeploymentRecordStore(connection, workspace=workspace)

        def reviewer(user):
            selected = copy(args)
            selected.user_id = user
            return operator(selected)

        reviews = IncidentSourceReview(
            records,
            SourceArtifactService(S3SourceArtifactStore(storage)) if verify else None,
            clock=lambda: datetime.now(UTC).isoformat(),
            revalidate=lambda: operator(args),
            reviewer=reviewer,
        )
        ledger = PostgresSourceBuildApprovals(records, revalidate=lambda: operator(args))
        ledger.check_ready()
        service = IncidentSourceBuildApproval(
            reviews,
            ledger,
            settings,
            clock=lambda: datetime.now(UTC).isoformat(),
            reviewer=reviewer,
        )
        options = {
            "incident_id": args.incident_id,
            "expected_boundary": args.expected_boundary,
            "expected_revision": args.expected_revision,
        }
        common = dict(approval_id=args.source_build_approval_id, **options)
        if approve:
            report = service.approve(
                actor,
                args.job_id,
                review_id=args.source_review_id,
                build_id=args.source_build_id,
                review_ref=args.source_build_ref,
                seconds=seconds,
                **common,
            )
        elif revoke:
            report = service.revoke(actor, args.job_id, review_ref=args.source_build_ref, **common)
        elif verify:
            report = service.check(actor, args.job_id, **common)
        else:
            report = service.inspect(actor, args.job_id, **common)
        print(json.dumps({"incident_source_build": report}, sort_keys=True))
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
            "Source build consent unavailable or write outcome uncertain; inspect ledger, never automatically retry or dispatch.\n",
        )
