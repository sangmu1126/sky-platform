"""Trusted CLI only: operator-selected membership is not a browser login.

Requires both OS/AWS/database access and an explicit current admin membership.
No arbitrary role flag, migrations, allocation, or queue messages.
Explicitly confirmed DB restriction disables only a registered shared/dedicated app login.
Only explicitly reviewed false positives may be released; real incident recovery is separate.
Observe invokes the fixed ownership-checking probe; it cannot accept user URLs or receipts.
"""

import json
import os
import re
from contextlib import contextmanager
from datetime import UTC, datetime

from adapters.aws.dedicated_incident import AwsDedicatedIncidentDatabase
from adapters.aws.shared_database import AwsSharedDatabaseAllocator
from adapters.state.postgres import (
    PostgresDeploymentRecordStore,
    PostgresStateSettings,
    RotatingDatabaseConnection,
)
from adapters.state.readiness import check_database_ready
from application.deployment_observation import DeploymentObservationRecorder
from application.deployment_writes import DeploymentMetadataWriter
from application.health import check_deployment
from application.incident_credential_preparation import IncidentCredentialPreparation
from application.incident_database_restriction import IncidentDatabaseRestriction
from application.security_hold import SecurityHold, validate_hold_request, validate_release_request
from domain.access import LoginSource, Principal, Role
from domain.database import DatabaseBinding
from interfaces.b_preparation_runtime import preparation_identity
from interfaces.incident_database_registration import load_dedicated_incident_registration
from interfaces.incident_secret_registration import load_secret_registration
from interfaces.shared_database_worker import current_membership, load_pool_configuration
from ports.state import RecordConflict


def operator(args):
    identity = preparation_identity(args)
    if args.auth_mode == "cognito":
        matches = [
            Principal(*record, LoginSource.EXTERNAL_IDP)
            for (issuer, _), record in identity.memberships.records.items()
            if issuer == identity.settings.issuer and record[:2] == (args.user_id, args.organization_id)
        ]
        if len(matches) != 1:
            raise PermissionError("Administrator membership is missing or ambiguous")
        actor = matches[0]
    else:
        actor = current_membership(identity, args.user_id, args.organization_id)
    if actor.role is not Role.ADMIN:
        raise PermissionError("Current administrator membership required")
    return actor


def run_security_hold(args, parser):
    now = datetime.now(UTC).isoformat()
    database_action = args.action in {
        "restrict-database",
        "inspect-database",
        "prepare-credentials",
        "inspect-credentials",
    }
    runtime_action = args.action in {
        "inspect-runtime",
        "contain-runtime",
        "inspect-runtime-containment",
    }
    image_action = args.action == "inspect-recovery-image"
    readiness_action = args.action == "check-recovery-readiness"
    readiness_configuration = None
    review_action = args.action in {
        "approve-artifact-review",
        "check-artifact-review",
        "check-recovery-readiness",
        "revoke-artifact-review",
    }
    combined_action = args.action in {
        "inspect-build-image",
        "approve-artifact-review",
        "check-artifact-review",
        "check-recovery-readiness",
    }
    build_action = args.action == "inspect-build-approval" or combined_action
    build_registration = None
    image_registration = None
    provenance_policy, provenance_verifier = None, None
    executor_action = args.action == "inspect-credential-executor"
    secret_action = args.action in {"fence-secret-access", "inspect-secret-access"}
    secret_registration = None
    dedicated_registration = None
    try:
        if not re.fullmatch(r"[a-f0-9]{16}", args.job_id):
            raise ValueError("Invalid deployment identity")
        if review_action:
            validate_release_request(
                args.incident_id,
                args.artifact_review_ref or "artifact-review",
                args.expected_revision,
                args.expected_boundary,
                now,
            )
            if not re.fullmatch(r"[a-f0-9]{32}", args.artifact_review_id or ""):
                raise ValueError("Exact artifact review identity required")
            if args.confirm_artifact_review != (
                args.action == "approve-artifact-review"
            ) or args.confirm_artifact_review_revocation != (args.action == "revoke-artifact-review"):
                raise ValueError("Explicit disjoint artifact review confirmation required")
            if args.action in {"check-artifact-review", "check-recovery-readiness"}:
                if args.artifact_review_ref is not None or args.artifact_review_seconds is not None:
                    raise ValueError("Review check cannot change reference or validity")
            elif args.artifact_review_ref is None:
                raise ValueError("Separate artifact review reference required")
            if args.action != "approve-artifact-review" and args.artifact_review_seconds is not None:
                raise ValueError("Review validity requires approval")
            if args.artifact_review_seconds is not None and not 1 <= args.artifact_review_seconds <= 900:
                raise ValueError("Bounded artifact review validity required")
            if any((args.reason, args.confirm_hold, args.review_ref, args.confirm_false_positive)):
                raise ValueError("Artifact review cannot release or replace a hold")
        elif any(
            (
                args.artifact_review_id,
                args.artifact_review_ref,
                args.artifact_review_seconds is not None,
                args.confirm_artifact_review,
                args.confirm_artifact_review_revocation,
            )
        ):
            raise ValueError("Artifact review options require a review action")
        if args.confirm_runtime_containment != (args.action == "contain-runtime"):
            raise ValueError("Explicit runtime containment confirmation required only for containment")
        if args.confirm_secret_access_fence != (args.action == "fence-secret-access"):
            raise ValueError("Explicit Secret access confirmation required only for fencing")
        if secret_action:
            secret_registration = load_secret_registration(args.incident_secret_config)
            validate_release_request(
                args.incident_id, "secret-access", args.expected_revision, args.expected_boundary, now
            )
            if args.action == "fence-secret-access" and args.expected_operation_id is not None:
                raise ValueError("New Secret access fence cannot select an existing operation")
            if args.action == "inspect-secret-access" and not re.fullmatch(
                r"[a-f0-9]{32}", args.expected_operation_id or ""
            ):
                raise ValueError("Exact Secret access operation required")
            if any((args.reason, args.confirm_hold, args.review_ref, args.confirm_false_positive)):
                raise ValueError("Secret access actions cannot release or replace a hold")
        elif args.action == "status" and (
            args.incident_secret_config or "SKY_INCIDENT_SECRET_ACCESS_JSON" in os.environ
        ):
            secret_registration = load_secret_registration(args.incident_secret_config)
        elif args.incident_secret_config and not readiness_action:
            raise ValueError("Secret access registration requires a Secret access action or status")
        if image_action or combined_action:
            from interfaces.recovery_image_registration import load_recovery_image_registration

            image_registration = load_recovery_image_registration(args.recovery_image_config)
            validate_release_request(
                args.incident_id, "recovery-image", args.expected_revision, args.expected_boundary, now
            )
            if any((args.reason, args.confirm_hold, args.review_ref, args.confirm_false_positive)):
                raise ValueError("Recovery image inspection cannot mutate a hold")
        elif args.recovery_image_config:
            raise ValueError("Recovery image registration requires image inspection")
        if build_action:
            from interfaces.kms_build_registration import load_build_approval_registration

            build_registration = load_build_approval_registration(args.build_approval_config)
            validate_release_request(
                args.incident_id, "build-approval", args.expected_revision, args.expected_boundary, now
            )
            if any((args.reason, args.confirm_hold, args.review_ref, args.confirm_false_positive)):
                raise ValueError("Build approval inspection cannot mutate a hold")
            if combined_action:
                b, r = build_registration, image_registration
                if (
                    r.organization_id,
                    r.job_id,
                    r.incident_id,
                    r.boundary_id,
                    r.account_id,
                    r.region,
                    r.manifest_digest,
                    r.config_digest,
                    r.source_revision,
                    r.build_reference,
                ) != (
                    args.organization_id,
                    args.job_id,
                    args.incident_id,
                    args.expected_boundary,
                    b.settings.account_id,
                    b.settings.region,
                    b.image_digest,
                    b.config_digest,
                    b.settings.workflow_sha,
                    f"https://github.com/{b.settings.repository}/actions/runs/{b.run_id}",
                ):
                    raise ValueError("Image and build registration pins differ")
        elif args.build_approval_config:
            raise ValueError("Build approval registration requires build approval inspection")
        if args.recovery_provenance_config:
            if not image_action:
                raise ValueError("Provenance verification requires recovery image inspection")
            from adapters.github.recovery_provenance import GitHubRecoveryProvenance
            from domain.recovery_provenance import expected_provenance
            from interfaces.recovery_provenance_registration import load_recovery_provenance_registration

            provenance_policy, paths = load_recovery_provenance_registration(args.recovery_provenance_config)
            expected_provenance(image_registration, provenance_policy)
            provenance_verifier = GitHubRecoveryProvenance(provenance_policy, **paths)
        if executor_action:
            validate_release_request(
                args.incident_id, "credential-executor", args.expected_revision, args.expected_boundary, now
            )
            if not re.fullmatch(r"[a-f0-9]{32}", args.expected_operation_id or ""):
                raise ValueError("Exact credential preparation operation required")
            if any((args.reason, args.confirm_hold, args.review_ref, args.confirm_false_positive)):
                raise ValueError("Executor inspection cannot mutate a hold")
        if runtime_action:
            if args.action == "contain-runtime" and args.expected_operation_id is not None:
                raise ValueError("New containment cannot select an existing operation")
            if args.action == "inspect-runtime-containment" and not re.fullmatch(
                r"[a-f0-9]{32}", args.expected_operation_id or ""
            ):
                raise ValueError("Exact containment operation required")
            validate_release_request(
                args.incident_id, "runtime-inspection", args.expected_revision, args.expected_boundary, now
            )
            if any((args.reason, args.confirm_hold, args.review_ref, args.confirm_false_positive)):
                raise ValueError("Runtime inspection cannot mutate a hold")
        if database_action:
            validate_release_request(
                args.incident_id, "database-operator", args.expected_revision, args.expected_boundary, now
            )
            if args.action == "restrict-database":
                if not args.confirm_database_restriction or args.expected_operation_id is not None:
                    raise ValueError("Explicit database restriction confirmation required")
            elif args.confirm_database_restriction or not re.fullmatch(
                r"[a-f0-9]{32}", args.expected_operation_id or ""
            ):
                raise ValueError("Exact restriction operation required for read-only inspection")
            if args.action == "prepare-credentials":
                if not args.confirm_credential_preparation:
                    raise ValueError("Explicit credential preparation confirmation required")
            elif args.confirm_credential_preparation:
                raise ValueError("Credential confirmation requires credential preparation")
            if any((args.reason, args.confirm_hold, args.review_ref, args.confirm_false_positive)):
                raise ValueError("Database actions cannot release or replace a hold")
            pool_settings, _ = load_pool_configuration(args.pool_config)
            if args.dedicated_incident_config or "SKY_DEDICATED_INCIDENT_JSON" in os.environ:
                dedicated_registration = load_dedicated_incident_registration(
                    args.dedicated_incident_config, pool_settings
                )
        elif not readiness_action and any(
            (
                args.pool_config,
                args.confirm_database_restriction,
                args.expected_operation_id
                if args.action
                not in {"inspect-runtime-containment", "inspect-secret-access", "inspect-credential-executor"}
                else None,
                args.dedicated_incident_config,
                args.confirm_credential_preparation,
            )
        ):
            raise ValueError("Database options require a database action")
        release_options = (
            args.review_ref,
            args.expected_revision,
            args.expected_boundary,
            args.confirm_false_positive,
        )
        if args.action == "release-false-positive":
            if not args.confirm_false_positive or args.reason is not None or args.confirm_hold:
                raise ValueError("Explicit false-positive review confirmation required")
            validate_release_request(
                args.incident_id, args.review_ref, args.expected_revision, args.expected_boundary, now
            )
        elif (
            not database_action
            and not runtime_action
            and not secret_action
            and not executor_action
            and not image_action
            and not build_action
            and not review_action
            and any(value is not None and value is not False for value in release_options)
        ):
            raise ValueError("Release options require the false-positive release action")
        if args.action == "place":
            if not args.confirm_hold:
                raise ValueError("Explicit hold confirmation required")
            validate_hold_request(args.incident_id, args.reason, now)
        elif (
            not database_action
            and not runtime_action
            and not secret_action
            and not executor_action
            and not image_action
            and not build_action
            and not review_action
            and args.action != "release-false-positive"
            and (args.incident_id is not None or args.reason is not None or args.confirm_hold)
        ):
            raise ValueError("Observation/status cannot include hold mutation options")
        if readiness_action and any(
            (
                args.confirm_database_restriction,
                args.confirm_credential_preparation,
                args.expected_operation_id,
            )
        ):
            raise ValueError("Readiness uses recorded operation IDs and cannot mutate database state")
        state = PostgresStateSettings.from_environment()
        if readiness_action:
            from interfaces.recovery_readiness import load_readiness_configuration

            readiness_configuration = load_readiness_configuration(args, state)
        if database_action and (
            state.region != pool_settings.pool.region
            or state.secret_arn.split(":")[4] != pool_settings.pool.account_id
            or state.secret_arn == pool_settings.admin_secret_arn
            or state.database == pool_settings.pool.control_database
        ):
            raise ValueError("Separate registered state and workload databases required")
        if dedicated_registration and state.secret_arn == dedicated_registration.admin_secret_arn:
            raise ValueError("Dedicated workload cannot use Sky state credentials")
        if secret_registration and (
            state.region != secret_registration.binding.region
            or state.secret_arn.split(":")[4] != secret_registration.binding.account_id
            or state.secret_arn == secret_registration.secret_arn
        ):
            raise ValueError("Separate state and registered workload Secret required")
        workspace = os.environ.get("SKY_STATE_WORKSPACE", "team")
        PostgresDeploymentRecordStore(None, workspace=workspace)
        actor = operator(args)
    except (ValueError, TypeError, KeyError, PermissionError, OSError):
        parser.error("Invalid security hold configuration, confirmation or current administrator")
    if args.check_config:
        print("Configuration valid: security hold; no AWS/DB calls", flush=True)
        return
    from botocore.exceptions import BotoCoreError, ClientError
    from psycopg import Error as DatabaseError

    try:
        factory = RotatingDatabaseConnection(state)

        @contextmanager
        def connection():
            with factory() as db:
                if args.action in {
                    "status",
                    "inspect-database",
                    "inspect-credentials",
                    "inspect-runtime",
                    "inspect-runtime-containment",
                    "inspect-secret-access",
                    "inspect-credential-executor",
                    "inspect-recovery-image",
                    "inspect-build-approval",
                    "inspect-build-image",
                    "check-artifact-review",
                    "check-recovery-readiness",
                }:
                    db.execute("SET TRANSACTION READ ONLY")
                yield db

        check_database_ready(connection)
        records = PostgresDeploymentRecordStore(connection, workspace=workspace)
        service = SecurityHold(records)
        if operator(args) != actor:
            raise PermissionError("Administrator membership changed")
        if args.action == "place":
            service.place(actor, args.job_id, incident_id=args.incident_id, reason=args.reason, now=now)
        if args.action == "release-false-positive":
            service.release_false_positive(
                actor,
                args.job_id,
                incident_id=args.incident_id,
                review_ref=args.review_ref,
                expected_revision=args.expected_revision,
                expected_boundary=args.expected_boundary,
                now=now,
            )
        build_report = None
        review_report = None
        readiness_report = None
        if build_action:
            from adapters.aws.kms_build_key import AwsKmsBuildKeyObserver
            from adapters.aws.recovery_image import AwsRecoveryImageInspector
            from adapters.state.build_approval import PostgresBuildApprovalReader
            from adapters.state.operations import PostgresOperationStore
            from application.incident_build_approval import IncidentBuildApprovalInspection

            inspector = IncidentBuildApprovalInspection(
                records,
                PostgresBuildApprovalReader(
                    PostgresOperationStore(connection, workspace=workspace), build_registration.settings
                ),
                build_registration.identity,
                clock=lambda: datetime.now(UTC).isoformat(),
                revalidate=lambda: operator(args),
                key_observer=AwsKmsBuildKeyObserver(build_registration.identity),
                image_registration=image_registration if combined_action else None,
                image_inspector=AwsRecoveryImageInspector() if combined_action else None,
            )
            options = {
                "incident_id": args.incident_id,
                "expected_boundary": args.expected_boundary,
                "expected_revision": args.expected_revision,
                "bundle": build_registration.bundle,
                "image_digest": build_registration.image_digest,
                "config_digest": build_registration.config_digest,
                "run_id": build_registration.run_id,
            }
            if review_action:
                from copy import copy

                from application.incident_artifact_review import IncidentArtifactReview

                def reviewer(user_id):
                    selected = copy(args)
                    selected.user_id = user_id
                    return operator(selected)

                reviews = IncidentArtifactReview(
                    records,
                    inspector,
                    clock=lambda: datetime.now(UTC).isoformat(),
                    revalidate=lambda: operator(args),
                    reviewer=reviewer,
                )
                if args.action == "approve-artifact-review":
                    review_report = reviews.approve(
                        actor,
                        args.job_id,
                        review_id=args.artifact_review_id,
                        review_ref=args.artifact_review_ref,
                        seconds=args.artifact_review_seconds or 900,
                        **options,
                    )
                elif readiness_action:
                    from application.incident_recovery_readiness import IncidentRecoveryReadiness
                    from interfaces.recovery_readiness import native_inspections

                    readiness_report = IncidentRecoveryReadiness(
                        records,
                        reviews,
                        native_inspections(
                            records,
                            state,
                            readiness_configuration,
                            clock=lambda: datetime.now(UTC).isoformat(),
                            revalidate=lambda: operator(args),
                        ),
                        clock=lambda: datetime.now(UTC).isoformat(),
                        revalidate=lambda: operator(args),
                    ).check(actor, args.job_id, review_id=args.artifact_review_id, **options)
                else:
                    review_report = reviews.check(
                        actor, args.job_id, review_id=args.artifact_review_id, **options
                    )
            else:
                build_report = inspector.inspect(actor, args.job_id, **options)
        if args.action == "revoke-artifact-review":
            from application.incident_artifact_review import IncidentArtifactReview

            review_report = IncidentArtifactReview(
                records,
                None,
                clock=lambda: datetime.now(UTC).isoformat(),
                revalidate=lambda: operator(args),
                reviewer=None,
            ).revoke(
                actor,
                args.job_id,
                review_id=args.artifact_review_id,
                review_ref=args.artifact_review_ref,
                incident_id=args.incident_id,
                expected_boundary=args.expected_boundary,
                expected_revision=args.expected_revision,
            )
        image_report = None
        if image_action:
            from adapters.aws.recovery_image import AwsRecoveryImageInspector
            from application.recovery_image_inspection import RecoveryImageInspection

            image_report = RecoveryImageInspection(
                records,
                image_registration,
                AwsRecoveryImageInspector(provenance=provenance_verifier),
                clock=lambda: datetime.now(UTC).isoformat(),
                revalidate=lambda: operator(args),
                provenance_policy=provenance_policy,
            ).inspect(
                actor,
                args.job_id,
                incident_id=args.incident_id,
                expected_boundary=args.expected_boundary,
                expected_revision=args.expected_revision,
            )
        executor_report = None
        if executor_action:
            from adapters.aws.credential_executor import AwsCredentialExecutorObserver
            from application.credential_executor_inspection import CredentialExecutorInspection

            executor_report = CredentialExecutorInspection(
                records,
                AwsCredentialExecutorObserver(),
                clock=lambda: datetime.now(UTC).isoformat(),
                revalidate=lambda: operator(args),
            ).inspect(
                actor,
                args.job_id,
                incident_id=args.incident_id,
                expected_boundary=args.expected_boundary,
                expected_revision=args.expected_revision,
                expected_operation_id=args.expected_operation_id,
            )
        secret_report = None
        if secret_action:
            from adapters.aws.incident_secret_access import AwsIncidentSecretAccess
            from application.incident_secret_access import IncidentSecretAccess

            secret_service = IncidentSecretAccess(
                records,
                secret_registration,
                AwsIncidentSecretAccess(secret_registration),
                clock=lambda: datetime.now(UTC).isoformat(),
                revalidate=lambda: operator(args),
            )
            options = {
                "incident_id": args.incident_id,
                "expected_boundary": args.expected_boundary,
                "expected_revision": args.expected_revision,
            }
            if args.action == "fence-secret-access":
                secret_report = secret_service.fence(actor, args.job_id, **options)
            else:
                secret_report = secret_service.inspect(
                    actor, args.job_id, expected_operation_id=args.expected_operation_id, **options
                )
        runtime_report = None
        containment_report = None
        if runtime_action:
            import boto3
            from botocore.config import Config

            from adapters.aws.incident_containment import AwsIncidentRuntimeContainment
            from adapters.aws.incident_runtime import AwsIncidentRuntimeInspection
            from application.incident_runtime_containment import IncidentRuntimeContainment
            from application.incident_runtime_inspection import IncidentRuntimeInspection
            from domain.incident_runtime import runtime_identity

            recorded = DeploymentMetadataWriter(records).snapshot(actor, args.job_id)
            _, runtime_region, *_ = runtime_identity(recorded.record.get("result"))
            client = boto3.client(
                "ecs",
                region_name=runtime_region,
                config=Config(retries={"total_max_attempts": 1, "mode": "standard"}),
            )
            sts = boto3.client("sts", region_name=runtime_region)
            options = {
                "incident_id": args.incident_id,
                "expected_boundary": args.expected_boundary,
                "expected_revision": args.expected_revision,
            }
            if args.action == "inspect-runtime":
                runtime_report = IncidentRuntimeInspection(
                    records,
                    AwsIncidentRuntimeInspection(client=client, sts=sts),
                    clock=lambda: datetime.now(UTC).isoformat(),
                    revalidate=lambda: operator(args),
                ).inspect(actor, args.job_id, **options)
            else:
                adapter = AwsIncidentRuntimeContainment(
                    client=client,
                    sts=sts,
                    autoscaling=boto3.client(
                        "application-autoscaling",
                        region_name=runtime_region,
                        config=Config(retries={"total_max_attempts": 1, "mode": "standard"}),
                    ),
                )
                containment = IncidentRuntimeContainment(
                    records,
                    adapter,
                    clock=lambda: datetime.now(UTC).isoformat(),
                    revalidate=lambda: operator(args),
                )
                if args.action == "contain-runtime":
                    containment_report = containment.request(actor, args.job_id, **options)
                else:
                    containment_report = containment.inspect(
                        actor, args.job_id, expected_operation_id=args.expected_operation_id, **options
                    )
        database_report = None
        credential_report = None
        if database_action:
            writer = DeploymentMetadataWriter(records)
            snapshot = writer.snapshot(actor, args.job_id)
            binding = DatabaseBinding(**snapshot.record["workload_database_binding"])

            def guard():
                if operator(args) != actor:
                    raise PermissionError("Administrator membership changed")
                current = writer.snapshot(actor, args.job_id)
                if current != snapshot:
                    raise RecordConflict("Deployment changed during database registration checks")

            def membership_guard():
                if operator(args) != actor:
                    raise PermissionError("Administrator membership changed")

            guard()
            if binding.role == "dedicated_workload":
                if dedicated_registration is None or dedicated_registration.binding != binding:
                    raise ValueError("Exact dedicated application registration required")
                provider = AwsDedicatedIncidentDatabase(dedicated_registration)
            elif binding.role == "shared_workload" and dedicated_registration is None:
                provider = AwsSharedDatabaseAllocator(pool_settings)
            else:
                raise ValueError("Database role differs from incident registration")
            preparation = None
            if args.action in {"prepare-credentials", "inspect-credentials"}:
                preparation = provider.incident_credential_preparation(
                    binding, state, guard=guard, connection_guard=membership_guard
                )
                adapter = preparation.restriction
            else:
                adapter = provider.incident_restriction(
                    binding, state, guard=guard, connection_guard=membership_guard
                )

            # Once the application service records intent, its own guards replace
            # the bootstrap snapshot guard; connection guards still recheck admin.
            def current_operator():
                return operator(args)

            restriction = IncidentDatabaseRestriction(
                records,
                adapter,
                clock=lambda: datetime.now(UTC).isoformat(),
                revalidate=current_operator,
            )
            options = {
                "incident_id": args.incident_id,
                "expected_boundary": args.expected_boundary,
                "expected_revision": args.expected_revision,
            }
            if args.action in {"prepare-credentials", "inspect-credentials"}:
                from adapters.aws.preparation_executor import load_preparation_executor_identity

                executor = (
                    load_preparation_executor_identity(
                        os.environ.get("ECS_CONTAINER_METADATA_URI_V4"),
                        account_id=binding.account_id,
                        region=binding.region,
                    )
                    if args.action == "prepare-credentials"
                    else None
                )
                credential_service = IncidentCredentialPreparation(
                    records,
                    adapter,
                    preparation,
                    clock=lambda: datetime.now(UTC).isoformat(),
                    revalidate=current_operator,
                    executor=executor,
                )
                command = (
                    credential_service.prepare
                    if args.action == "prepare-credentials"
                    else credential_service.inspect
                )
                credential_report = command(
                    actor, args.job_id, expected_operation_id=args.expected_operation_id, **options
                )
                database_report = restriction.status(actor, args.job_id)
            elif args.action == "restrict-database":
                database_report = restriction.restrict(actor, args.job_id, **options)
            else:
                database_report = restriction.inspect(
                    actor, args.job_id, expected_operation_id=args.expected_operation_id, **options
                )
        observation = None
        if args.action == "observe":
            observation = DeploymentObservationRecorder(
                records,
                check_deployment,
                clock=lambda: datetime.now(UTC).isoformat(),
                revalidate=lambda: operator(args),
            ).collect(actor, args.job_id)
        if args.action == "status":
            database_report = IncidentDatabaseRestriction(
                records, None, clock=lambda: now, revalidate=lambda: operator(args)
            ).status(actor, args.job_id)
        if args.action == "status":
            credential_report = IncidentCredentialPreparation(
                records, None, None, clock=lambda: now, revalidate=lambda: operator(args)
            ).status(actor, args.job_id)
        if args.action == "status":
            from application.incident_runtime_containment import IncidentRuntimeContainment

            containment_report = IncidentRuntimeContainment(
                records, None, clock=lambda: now, revalidate=lambda: operator(args)
            ).status(actor, args.job_id)
        if args.action == "status":
            from application.incident_secret_access import IncidentSecretAccess

            secret_report = IncidentSecretAccess(
                records, secret_registration, None, clock=lambda: now, revalidate=lambda: operator(args)
            ).status(actor, args.job_id)
        report = service.status(actor, args.job_id)
        if build_report is not None and (
            report.get("metadata_revision") != build_report["metadata_revision"]
            or report.get("record_valid") is not True
            or not isinstance(report.get("hold"), dict)
            or report["hold"].get("incident_id") != args.incident_id
            or not isinstance(report.get("review_boundary"), dict)
            or report["review_boundary"].get("id") != args.expected_boundary
        ):
            raise RecordConflict("Deployment changed before build inspection output")
        if review_report is not None and (
            report.get("metadata_revision") != review_report["metadata_revision"]
            or not isinstance(report.get("review_boundary"), dict)
            or report["review_boundary"].get("id") != args.expected_boundary
            or report.get("record_valid") is not True
        ):
            raise RecordConflict("Deployment changed before artifact review output")
        if readiness_report is not None and (
            report.get("metadata_revision") != readiness_report["metadata_revision"]
            or not isinstance(report.get("review_boundary"), dict)
            or report["review_boundary"].get("id") != args.expected_boundary
            or report.get("record_valid") is not True
        ):
            raise RecordConflict("Deployment changed before readiness output")
        if operator(args) != actor:
            raise PermissionError("Administrator membership changed")
        print(
            json.dumps(
                {
                    **report,
                    "observed_only": args.action
                    in {
                        "status",
                        "inspect-database",
                        "inspect-credentials",
                        "inspect-runtime",
                        "inspect-runtime-containment",
                        "inspect-secret-access",
                        "inspect-credential-executor",
                        "inspect-recovery-image",
                        "inspect-build-approval",
                        "inspect-build-image",
                        "check-artifact-review",
                        "check-recovery-readiness",
                    },
                    **({"database_restriction": database_report} if database_report is not None else {}),
                    **({"health_observation": observation} if observation is not None else {}),
                    **(
                        {"credential_preparation": credential_report} if credential_report is not None else {}
                    ),
                    **({"runtime_inspection": runtime_report} if runtime_report is not None else {}),
                    **({"runtime_containment": containment_report} if containment_report is not None else {}),
                    **({"secret_access_fence": secret_report} if secret_report is not None else {}),
                    **({"recovery_image": image_report} if image_report is not None else {}),
                    **({"build_approval": build_report} if build_report is not None else {}),
                    **({"artifact_review": review_report} if review_report is not None else {}),
                    **({"recovery_readiness": readiness_report} if readiness_report is not None else {}),
                    **({"credential_executor": executor_report} if executor_report is not None else {}),
                    "quarantine_performed": False,
                    "credentials_revoked": False,
                }
            ),
            flush=True,
        )
    except (
        ValueError,
        TypeError,
        KeyError,
        PermissionError,
        FileNotFoundError,
        OSError,
        RecordConflict,
        BotoCoreError,
        ClientError,
        DatabaseError,
    ):
        parser.exit(
            1,
            "Security hold outcome could not be confirmed. Inspect status before retrying; no automatic release is performed.\n",
        )
