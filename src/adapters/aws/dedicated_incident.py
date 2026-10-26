"""Existing dedicated workload only: no create, app Secret reads or LOGIN restore.

Registration is trusted operator configuration, bound to one app and immutable
RDS resource ID. The former shared pool need not be available during an incident.
"""

import re
from dataclasses import dataclass, replace
from uuid import UUID

from adapters.aws.dedicated_database import AwsDedicatedDatabasePreparer, DedicatedDatabaseSettings
from adapters.aws.shared_database import AwsSharedDatabaseAllocator
from adapters.database.dedicated_access import PostgresDedicatedAccess, access_identity
from adapters.database.incident_restriction import PostgresIncidentRestriction
from adapters.database.promotion_fence import PostgresApplicationFence
from domain.database import DatabaseBinding


@dataclass(frozen=True)
class DedicatedIncidentRegistration:
    settings: DedicatedDatabaseSettings
    binding: DatabaseBinding
    operation_id: str
    plan_id: str
    resource_id: str
    admin_secret_arn: str
    connection_limit: int

    def __post_init__(self):
        if not isinstance(self.settings, DedicatedDatabaseSettings) or not isinstance(
            self.binding, DatabaseBinding
        ):
            raise TypeError("Explicit dedicated settings and application binding required")
        target, source = self.binding, self.settings.source
        access_identity(target)
        if (
            (target.account_id, target.region) != (source.pool.account_id, source.pool.region)
            or target.instance_id == source.pool.instance_id
            or not re.fullmatch(r"sky-[a-z][a-z0-9-]{2,55}", target.instance_id)
            or "--" in target.instance_id
            or target.instance_id.endswith("-")
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", target.database_name)
            or target.database_name.startswith(("sky_pool_", "sky_state"))
            or not isinstance(self.operation_id, str)
            or str(UUID(self.operation_id)) != self.operation_id
            or not isinstance(self.plan_id, str)
            or not re.fullmatch(r"DBP-[a-f0-9]{16}", self.plan_id)
            or not isinstance(self.resource_id, str)
            or not re.fullmatch(r"db-[A-Za-z0-9]{1,64}", self.resource_id)
            or type(self.connection_limit) is not int
            or not 1 <= self.connection_limit <= 50
            or self.admin_secret_arn == source.admin_secret_arn
        ):
            raise ValueError("Dedicated incident registration identity differs from workload scope")
        # Reuse strict same-account Secret ARN and pinned network validation.
        replace(
            source,
            admin_secret_arn=self.admin_secret_arn,
            database_security_group=self.settings.database_security_group,
        )


class AwsDedicatedIncidentDatabase:
    def __init__(self, registration, *, session=None, connect=None):
        if not isinstance(registration, DedicatedIncidentRegistration):
            raise TypeError("Explicit dedicated incident registration required")
        self.registration = registration
        self.preparer = AwsDedicatedDatabasePreparer(registration.settings, session=session, connect=connect)
        self.access = AwsSharedDatabaseAllocator(
            replace(
                registration.settings.source,
                admin_secret_arn=registration.admin_secret_arn,
                database_security_group=registration.settings.database_security_group,
            ),
            session=session,
            connect=connect,
        )

    def incident_credential_preparation(self, binding, state, *, guard, connection_guard):
        from botocore.config import Config

        from adapters.aws.incident_credentials import (
            AwsIncidentCredentialPreparation,
            credential_preparation_principal,
        )

        restriction = self.incident_restriction(
            binding, state, guard=guard, connection_guard=connection_guard
        )
        principal = credential_preparation_principal(self.access.session, binding)
        return AwsIncidentCredentialPreparation(
            restriction,
            principal_arn=principal,
            resource_id=self.registration.resource_id,
            kms_key_arn=self.registration.settings.source.app_secret_kms_arn,
            client=self.access.session.client(
                "secretsmanager", region_name=binding.region, config=Config(retries={"total_max_attempts": 1})
            ),
        )

    def incident_verification(self, binding, state, registration, *, guard, connection_guard):
        from adapters.aws.incident_secret_access import AwsIncidentSecretAccess
        from adapters.aws.incident_verification import AwsIncidentVerification

        preparation = self.incident_credential_preparation(
            binding, state, guard=guard, connection_guard=connection_guard
        )

        cleanup = self.incident_restriction(binding, state, guard=guard, connection_guard=lambda: None)

        def endpoint():
            connection_guard()
            host = self._audit_target(state)
            connection_guard()
            return host

        def workload():
            host = endpoint()
            credentials = self.access._admin_credentials("skyadmin")
            return self.access._connection(host, 5432, binding.database_name, *credentials)

        def login(password):
            return self.access._connection(
                endpoint(), 5432, binding.database_name, preparation.restriction.fence.role, password
            )

        return AwsIncidentVerification(
            preparation,
            workload_connect=workload,
            login_connect=login,
            cleanup_restriction=cleanup,
            registration=registration,
            secret_access=AwsIncidentSecretAccess(registration, session=self.access.session),
        )

    def _audit_target(self, state):
        registration = self.registration
        target, settings = registration.binding, registration.settings
        if (
            state.region != target.region
            or state.secret_arn.split(":")[4] != target.account_id
            or state.secret_arn == registration.admin_secret_arn
            or any(client.meta.region_name != target.region for client in self.access.clients.values())
            or self.preparer.rds.meta.region_name != target.region
            or self.access.clients["sts"].get_caller_identity()["Account"] != target.account_id
        ):
            raise ValueError("Dedicated account, region or state Secret differs from registration")
        instance = self.preparer._describe(target.instance_id)
        if not instance or instance.get("DbiResourceId") != registration.resource_id:
            raise ValueError("Registered dedicated RDS resource is missing or replaced")
        self.preparer._verify(
            instance,
            target,
            {
                "sky-managed": "true",
                "sky-database-role": "dedicated_workload",
                "sky-operation-id": registration.operation_id,
                "sky-plan-id": registration.plan_id,
                "sky-organization-id": target.organization_id,
                "sky-application-id": target.application_id,
                "sky-owner-ref": target.owner_ref,
                "sky-configuration-digest": settings.digest,
            },
            available=True,
        )
        self.preparer.network._audit_network(5432)
        endpoint, secret = instance.get("Endpoint", {}), instance.get("MasterUserSecret", {})
        host = endpoint.get("Address")
        if (
            not isinstance(host, str)
            or not re.fullmatch(rf"[a-z0-9.-]+\.{re.escape(target.region)}\.rds\.amazonaws\.com", host)
            or host.lower().rstrip(".") == state.host.lower().rstrip(".")
            or endpoint.get("Port") != 5432
            or secret.get("SecretArn") != registration.admin_secret_arn
            or secret.get("SecretStatus") != "active"
        ):
            raise ValueError("Separate dedicated endpoint and active managed Secret required")
        return host

    def incident_restriction(self, binding, state, *, guard, connection_guard):
        registration = self.registration
        if binding != registration.binding:
            raise ValueError("Held deployment differs from registered dedicated application")

        def resolve(check):
            check()
            host = self._audit_target(state)
            check()
            credentials = self.access._admin_credentials("skyadmin")

            def raw():
                return self.access._connection(host, 5432, binding.database_name, *credentials)

            PostgresDedicatedAccess(raw, None).existing_access(
                binding, connection_limit=registration.connection_limit, guard=check
            )
            check()
            return raw

        resolve(guard)

        def connect():
            return resolve(connection_guard)()

        role, marker = access_identity(binding)
        return PostgresIncidentRestriction(PostgresApplicationFence(connect, binding, role, marker))
