"""Trusted-operator new-source snapshot review; no builder or recovery execution."""

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
from application.incident_source_review import IncidentSourceReview
from application.security_hold import validate_release_request
from application.source_artifacts import SourceArtifactService
from interfaces.kms_build_registration import document
from interfaces.security_hold import operator
from ports.artifacts import SourceArtifact
from ports.state import RecordConflict


def run_source_review(args, parser):
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
        "recovery_source_config",
        "source_review_id",
        "predecessor_review_id",
        "confirm_source_review_supersession",
        "source_review_ref",
        "source_review_seconds",
        "confirm_source_review",
        "confirm_source_review_revocation",
    }
    supersede = args.action == "supersede-source-review"
    approve = args.action == "approve-source-review"
    writes_review = approve or supersede
    revoke = args.action == "revoke-source-review"
    verify = writes_review or args.action == "check-source-review"
    try:
        if any(v is not None and v is not False for k, v in vars(args).items() if k not in allowed):
            raise ValueError("Source review cannot include other action options")
        if (
            args.confirm_source_review is not approve
            or args.confirm_source_review_revocation is not revoke
            or args.confirm_source_review_supersession is not supersede
        ):
            raise ValueError("Disjoint explicit review confirmations required")
        if supersede:
            if not re.fullmatch(r"[a-f0-9]{32}", args.predecessor_review_id or ""):
                raise ValueError("Exact predecessor required")
        elif args.predecessor_review_id is not None:
            raise ValueError("Predecessor requires explicit supersession")
        if not re.fullmatch(r"[a-f0-9]{16}", args.job_id or "") or not re.fullmatch(
            r"[a-f0-9]{32}", args.source_review_id or ""
        ):
            raise ValueError("Exact source review identity required")
        if bool(args.source_review_ref) != (writes_review or revoke) or (
            not writes_review and args.source_review_seconds is not None
        ):
            raise ValueError("Action-specific source review reference/lifetime required")
        seconds = args.source_review_seconds if args.source_review_seconds is not None else 900
        if type(seconds) is not int or not 1 <= seconds <= 900:
            raise ValueError("Bounded source review lifetime required")
        validate_release_request(
            args.incident_id,
            args.source_review_ref or "source-review-read",
            args.expected_revision,
            args.expected_boundary,
            datetime.now(UTC).isoformat(),
        )
        state = PostgresStateSettings.from_environment()
        workspace = os.environ.get("SKY_STATE_WORKSPACE", "team")
        PostgresDeploymentRecordStore(None, workspace=workspace)
        actor = operator(args)
        if verify:
            # This is an operator-owned descriptor, never a file inside the app ZIP.
            candidate = SourceArtifact.from_record(document(args.recovery_source_config, 16384))
            if candidate.kind != "original" or candidate.organization_id != actor.organization_id:
                raise ValueError("Same-organization original source required")
            storage = S3ArtifactSettings.from_environment()
            if storage.region != state.region or storage.account_id != state.secret_arn.split(":")[4]:
                raise ValueError("State/source account and region must match registered hosting")
        elif args.recovery_source_config is not None:
            raise ValueError("Metadata inspection/revocation does not load source configuration")
    except (OSError, ValueError, TypeError, KeyError, PermissionError):
        parser.error("Invalid new-source review scope, configuration, confirmation or administrator")
    if args.check_config:
        print("New-source review configuration valid; no AWS/DB calls")
        return
    from botocore.exceptions import BotoCoreError, ClientError
    from psycopg import Error as DatabaseError

    try:
        factory = RotatingDatabaseConnection(state)

        @contextmanager
        def connection():
            with factory() as db:
                if not writes_review and not revoke:
                    db.execute("SET TRANSACTION READ ONLY")
                yield db

        check_database_ready(connection)

        def reviewer(user):
            selected = copy(args)
            selected.user_id = user
            return operator(selected)

        service = IncidentSourceReview(
            PostgresDeploymentRecordStore(connection, workspace=workspace),
            SourceArtifactService(S3SourceArtifactStore(storage)) if verify else None,
            clock=lambda: datetime.now(UTC).isoformat(),
            revalidate=lambda: operator(args),
            reviewer=reviewer,
        )
        options = {
            "incident_id": args.incident_id,
            "expected_boundary": args.expected_boundary,
            "expected_revision": args.expected_revision,
        }
        if writes_review:
            method = service.supersede if supersede else service.approve
            predecessor = {"predecessor_review_id": args.predecessor_review_id} if supersede else {}
            report = method(
                actor,
                args.job_id,
                candidate=candidate,
                review_id=args.source_review_id,
                review_ref=args.source_review_ref,
                seconds=seconds,
                **predecessor,
                **options,
            )
        elif revoke:
            report = service.revoke(
                actor,
                args.job_id,
                review_id=args.source_review_id,
                review_ref=args.source_review_ref,
                **options,
            )
        elif verify:
            report = service.check(
                actor, args.job_id, candidate=candidate, review_id=args.source_review_id, **options
            )
        else:
            report = service.inspect(actor, args.job_id, review_id=args.source_review_id, **options)
        print(json.dumps({"incident_source_review": report}, sort_keys=True))
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
            "New-source review unavailable or write outcome uncertain; inspect persisted review, never automatically retry or execute.\n",
        )
