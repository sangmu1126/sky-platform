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
    database_action = args.action in {"restrict-database", "inspect-database", "prepare-credentials"}
    dedicated_registration = None
    try:
        if not re.fullmatch(r"[a-f0-9]{16}", args.job_id):
            raise ValueError("Invalid deployment identity")
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
        elif any(
            (
                args.pool_config,
                args.confirm_database_restriction,
                args.expected_operation_id,
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
        elif not database_action and any(
            value is not None and value is not False for value in release_options
        ):
            raise ValueError("Release options require the false-positive release action")
        if args.action == "place":
            if not args.confirm_hold:
                raise ValueError("Explicit hold confirmation required")
            validate_hold_request(args.incident_id, args.reason, now)
        elif (
            not database_action
            and args.action != "release-false-positive"
            and (args.incident_id is not None or args.reason is not None or args.confirm_hold)
        ):
            raise ValueError("Observation/status cannot include hold mutation options")
        state = PostgresStateSettings.from_environment()
        if database_action and (
            state.region != pool_settings.pool.region
            or state.secret_arn.split(":")[4] != pool_settings.pool.account_id
            or state.secret_arn == pool_settings.admin_secret_arn
            or state.database == pool_settings.pool.control_database
        ):
            raise ValueError("Separate registered state and workload databases required")
        if dedicated_registration and state.secret_arn == dedicated_registration.admin_secret_arn:
            raise ValueError("Dedicated workload cannot use Sky state credentials")
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
                if args.action in {"status", "inspect-database"}:
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
            if args.action == "prepare-credentials":
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
            if args.action == "prepare-credentials":
                credential_report = IncidentCredentialPreparation(
                    records,
                    adapter,
                    preparation,
                    clock=lambda: datetime.now(UTC).isoformat(),
                    revalidate=current_operator,
                ).prepare(actor, args.job_id, expected_operation_id=args.expected_operation_id, **options)
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
        report = service.status(actor, args.job_id)
        if operator(args) != actor:
            raise PermissionError("Administrator membership changed")
        print(
            json.dumps(
                {
                    **report,
                    "observed_only": args.action in {"status", "inspect-database"},
                    **({"database_restriction": database_report} if database_report is not None else {}),
                    **({"health_observation": observation} if observation is not None else {}),
                    **(
                        {"credential_preparation": credential_report} if credential_report is not None else {}
                    ),
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
