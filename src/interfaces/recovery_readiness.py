"""Fixed native read-only probes for the operator readiness command."""

from types import SimpleNamespace

from application.deployment_writes import DeploymentMetadataWriter
from domain.database import DatabaseBinding
from domain.incident_runtime import runtime_identity
from interfaces.incident_database_registration import load_dedicated_incident_registration
from interfaces.incident_secret_registration import load_secret_registration
from interfaces.shared_database_worker import load_pool_configuration
from ports.state import RecordConflict


def load_readiness_configuration(args, state):
    pool, dedicated, secret = None, None, None
    if args.pool_config:
        pool, _ = load_pool_configuration(args.pool_config)
        if (
            state.region != pool.pool.region
            or state.secret_arn.split(":")[4] != pool.pool.account_id
            or state.secret_arn == pool.admin_secret_arn
            or state.database == pool.pool.control_database
        ):
            raise ValueError("Separate registered state and workload database required")
    if args.dedicated_incident_config:
        if pool is None:
            raise ValueError("Dedicated registration requires the workload pool configuration")
        dedicated = load_dedicated_incident_registration(args.dedicated_incident_config, pool)
        if state.secret_arn == dedicated.admin_secret_arn:
            raise ValueError("Dedicated workload cannot use state credentials")
    if args.incident_secret_config:
        secret = load_secret_registration(args.incident_secret_config)
        if state.secret_arn == secret.secret_arn:
            raise ValueError("Workload Secret cannot use state credentials")
    return pool, dedicated, secret


def native_inspections(records, state, configuration, *, clock, revalidate):
    pool, dedicated, secret = configuration
    writer = DeploymentMetadataWriter(records)

    def clients(principal, job_id, *, scaling=False):
        import boto3
        from botocore.config import Config

        snapshot = writer.snapshot(principal, job_id)
        _, region, *_ = runtime_identity(snapshot.record.get("result"))
        session = boto3.Session(region_name=region)
        config = Config(
            retries={"total_max_attempts": 1, "mode": "standard"}, connect_timeout=5, read_timeout=10
        )
        names = ("ecs", "sts", "application-autoscaling") if scaling else ("ecs", "sts")
        return {name: session.client(name, region_name=region, config=config) for name in names}

    def runtime(principal, job_id, **options):
        from adapters.aws.incident_runtime import AwsIncidentRuntimeInspection
        from application.incident_runtime_inspection import IncidentRuntimeInspection

        c = clients(principal, job_id)
        return IncidentRuntimeInspection(
            records,
            AwsIncidentRuntimeInspection(client=c["ecs"], sts=c["sts"]),
            clock=clock,
            revalidate=revalidate,
        ).inspect(principal, job_id, **options)

    def containment(principal, job_id, **options):
        from adapters.aws.incident_containment import AwsIncidentRuntimeContainment
        from application.incident_runtime_containment import IncidentRuntimeContainment

        c = clients(principal, job_id, scaling=True)
        return IncidentRuntimeContainment(
            records,
            AwsIncidentRuntimeContainment(
                client=c["ecs"], sts=c["sts"], autoscaling=c["application-autoscaling"]
            ),
            clock=clock,
            revalidate=revalidate,
        ).inspect(principal, job_id, **options)

    def executor(principal, job_id, **options):
        from adapters.aws.credential_executor import AwsCredentialExecutorObserver
        from application.credential_executor_inspection import CredentialExecutorInspection

        return CredentialExecutorInspection(
            records, AwsCredentialExecutorObserver(), clock=clock, revalidate=revalidate
        ).inspect(principal, job_id, **options)

    def database(principal, job_id, credentials, **options):
        from adapters.aws.dedicated_incident import AwsDedicatedIncidentDatabase
        from adapters.aws.shared_database import AwsSharedDatabaseAllocator
        from application.incident_credential_preparation import IncidentCredentialPreparation
        from application.incident_database_restriction import IncidentDatabaseRestriction

        snapshot = writer.snapshot(principal, job_id)
        binding = DatabaseBinding(**snapshot.record["workload_database_binding"])

        def membership_guard():
            if revalidate() != principal:
                raise PermissionError("Current administrator membership changed")

        def guard():
            membership_guard()
            if writer.snapshot(principal, job_id) != snapshot:
                raise RecordConflict("Deployment changed during database registration checks")

        guard()
        if binding.role == "dedicated_workload" and dedicated is not None and dedicated.binding == binding:
            provider = AwsDedicatedIncidentDatabase(dedicated)
        elif binding.role == "shared_workload" and dedicated is None:
            provider = AwsSharedDatabaseAllocator(pool)
        else:
            raise ValueError("Exact registered workload database required")
        if credentials:
            preparation = provider.incident_credential_preparation(
                binding, state, guard=guard, connection_guard=membership_guard
            )
            service = IncidentCredentialPreparation(
                records, preparation.restriction, preparation, clock=clock, revalidate=revalidate
            )
        else:
            restriction = provider.incident_restriction(
                binding, state, guard=guard, connection_guard=membership_guard
            )
            service = IncidentDatabaseRestriction(records, restriction, clock=clock, revalidate=revalidate)
        return service.inspect(principal, job_id, **options)

    def secret_access(principal, job_id, **options):
        from adapters.aws.incident_secret_access import AwsIncidentSecretAccess
        from application.incident_secret_access import IncidentSecretAccess

        return IncidentSecretAccess(
            records, secret, AwsIncidentSecretAccess(secret), clock=clock, revalidate=revalidate
        ).inspect(principal, job_id, **options)

    def sky_execution(principal, job_id, **options):
        from adapters.state.incident_execution import PostgresIncidentExecutionControl
        from adapters.state.operations import PostgresOperationStore

        operations = PostgresOperationStore(records.connection_factory, workspace=records.workspace)
        receipt = PostgresIncidentExecutionControl(operations, revalidate=revalidate).inspect(
            principal, job_id, **options
        )
        return {**receipt, "observed_at": clock()}

    checks = {
        "sky_execution": SimpleNamespace(inspect=sky_execution),
        "runtime": SimpleNamespace(inspect=runtime),
        "runtime_containment": SimpleNamespace(inspect=containment),
        "credential_executor": SimpleNamespace(inspect=executor),
    }
    if pool is not None:
        checks["database_restriction"] = SimpleNamespace(
            inspect=lambda p, j, **kw: database(p, j, False, **kw)
        )
        checks["candidate_credentials"] = SimpleNamespace(
            inspect=lambda p, j, **kw: database(p, j, True, **kw)
        )
    if secret is not None:
        checks["secret_access"] = SimpleNamespace(inspect=secret_access)
    return checks
