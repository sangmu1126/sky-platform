"""Trusted-operator single-use recovery; no implicit worker or browser activation."""

import json
import os
import re
from copy import copy
from datetime import UTC, datetime

from adapters.state.operations import PostgresOperationStore
from adapters.state.postgres import PostgresStateSettings, RotatingDatabaseConnection
from adapters.state.readiness import check_database_ready
from application.incident_recovery import IncidentRecovery
from application.security_hold import validate_release_request
from domain.incident_recovery import RecoveryRuntimeRegistration
from interfaces.kms_build_registration import document, load_build_approval_registration
from interfaces.recovery_image_registration import load_recovery_image_registration
from interfaces.recovery_readiness import load_readiness_configuration
from interfaces.security_hold import operator
from ports.state import RecordConflict


def load_runtime_registration(path):
    value = document(path, 16384)
    if (
        not isinstance(value, dict)
        or set(value) != {"version", "registration"}
        or type(value["version"]) is not int
        or value["version"] != 1
        or not isinstance(value["registration"], dict)
    ):
        raise ValueError("Exact recovery runtime registration required")
    fields = dict(value["registration"])
    if not isinstance(fields.get("subnets"), list):
        raise TypeError("Registered subnet list required")
    fields["subnets"] = tuple(fields["subnets"])
    return RecoveryRuntimeRegistration(**fields)


def run_incident_recovery(args, parser):
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
        "pool_config",
        "dedicated_incident_config",
        "incident_secret_config",
        "build_approval_config",
        "recovery_image_config",
        "recovery_runtime_config",
        "recovery_id",
        "recovery_approval_ref",
        "recovery_seconds",
        "confirm_recovery_approval",
        "confirm_recovery_execution",
        "artifact_review_id",
    }
    approve = args.action == "approve-recovery"
    try:
        if any(value not in (None, False) for name, value in vars(args).items() if name not in allowed):
            raise ValueError("Recovery cannot include other action options")
        if args.confirm_recovery_approval != approve or args.confirm_recovery_execution == approve:
            raise ValueError("Explicit disjoint recovery confirmation required")
        if not re.fullmatch(r"[a-f0-9]{32}", args.recovery_id or ""):
            raise ValueError("Exact recovery identity required")
        if approve:
            if (
                not re.fullmatch(r"[a-f0-9]{32}", args.artifact_review_id or "")
                or not args.recovery_approval_ref
            ):
                raise ValueError("Separate artifact review and recovery approval reference required")
        elif (
            args.artifact_review_id is not None
            or args.recovery_approval_ref is not None
            or args.recovery_seconds is not None
        ):
            raise ValueError("Execution cannot change approval scope")
        seconds = args.recovery_seconds if args.recovery_seconds is not None else 300
        if not 1 <= seconds <= 900:
            raise ValueError("Bounded recovery approval lifetime required")
        validate_release_request(
            args.incident_id,
            args.recovery_approval_ref or "recovery-execution",
            args.expected_revision,
            args.expected_boundary,
            datetime.now(UTC).isoformat(),
        )
        state = PostgresStateSettings.from_environment()
        configuration = load_readiness_configuration(args, state)
        if configuration[0] is None or configuration[2] is None:
            raise ValueError("Registered workload database and exact Secret required")
        build = load_build_approval_registration(args.build_approval_config)
        image = load_recovery_image_registration(args.recovery_image_config)
        runtime = load_runtime_registration(args.recovery_runtime_config)
        if (
            (
                runtime.organization_id,
                runtime.application_id,
                runtime.job_id,
                runtime.incident_id,
                runtime.boundary_id,
                runtime.account_id,
                runtime.region,
            )
            != (
                image.organization_id,
                image.application_id,
                image.job_id,
                image.incident_id,
                image.boundary_id,
                image.account_id,
                image.region,
            )
            or (
                runtime.organization_id,
                runtime.job_id,
                runtime.incident_id,
                runtime.boundary_id,
                runtime.recovery_id,
            )
            != (args.organization_id, args.job_id, args.incident_id, args.expected_boundary, args.recovery_id)
            or (runtime.account_id, runtime.region) != (build.settings.account_id, build.settings.region)
        ):
            raise ValueError("Recovery runtime, image and builder registration scopes differ")
        actor = operator(args)
        workspace = os.environ.get("SKY_STATE_WORKSPACE", "team")
        PostgresOperationStore(None, workspace=workspace)
    except (OSError, ValueError, PermissionError, TypeError, KeyError):
        parser.error("Invalid recovery approval, scope, registration or administrator configuration")
    if args.check_config:
        print("Recovery execution configuration valid; no AWS/DB calls")
        return
    try:
        from adapters.aws.incident_recovery import AwsIncidentRecovery
        from adapters.aws.kms_build_key import AwsKmsBuildKeyObserver
        from adapters.aws.recovery_image import AwsRecoveryImageInspector
        from adapters.state.build_approval import PostgresBuildApprovalReader
        from adapters.state.incident_recovery import PostgresIncidentRecoveryCompletion
        from application.incident_artifact_review import IncidentArtifactReview
        from application.incident_build_approval import IncidentBuildApprovalInspection
        from interfaces.incident_verification import compose_verification

        connection = RotatingDatabaseConnection(state)
        check_database_ready(connection, operations=True)
        operations = PostgresOperationStore(connection, workspace=workspace)
        clock = lambda: datetime.now(UTC).isoformat()
        prerequisites, verification, _ = compose_verification(
            args, state, configuration, operations, actor, clock=clock
        )
        inspector = IncidentBuildApprovalInspection(
            operations.records,
            PostgresBuildApprovalReader(operations, build.settings),
            build.identity,
            clock=clock,
            revalidate=lambda: operator(args),
            key_observer=AwsKmsBuildKeyObserver(build.identity),
            image_registration=image,
            image_inspector=AwsRecoveryImageInspector(),
        )

        def reviewer(user):
            selected = copy(args)
            selected.user_id = user
            return operator(selected)

        reviews = IncidentArtifactReview(
            operations.records, inspector, clock=clock, revalidate=lambda: operator(args), reviewer=reviewer
        )
        service = IncidentRecovery(
            operations.records,
            prerequisites,
            reviews,
            AwsIncidentRecovery(runtime, verification, clock=clock),
            PostgresIncidentRecoveryCompletion(operations, revalidate=lambda: operator(args)),
            clock=clock,
            revalidate=lambda: operator(args),
            reviewer=reviewer,
        )
        options = {
            "incident_id": args.incident_id,
            "expected_boundary": args.expected_boundary,
            "expected_revision": args.expected_revision,
            "bundle": build.bundle,
            "image_digest": build.image_digest,
            "config_digest": build.config_digest,
            "run_id": build.run_id,
        }
        if approve:
            report = service.approve(
                actor,
                args.job_id,
                recovery_id=args.recovery_id,
                review_id=args.artifact_review_id,
                approval_ref=args.recovery_approval_ref,
                seconds=seconds,
                **options,
            )
        else:
            report = service.execute(actor, args.job_id, recovery_id=args.recovery_id, **options)
        print(json.dumps({"incident_recovery": report}, sort_keys=True))
    except (OSError, ValueError, PermissionError, FileNotFoundError, RecordConflict, KeyError):
        parser.exit(
            1,
            "Recovery outcome requires inspection; never automatically retry activation or an uncertain commit.\n",
        )
