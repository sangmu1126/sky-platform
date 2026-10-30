"""Trusted owner's registered pool preparation inside a fenced build operation.

The API has no database credentials. Source is restored as data; uploaded Python
is never imported. SQL executes as the limited app role with an independent
cancellation deadline. Every uncertain effect is retained for reconciliation.
"""

import json
from dataclasses import asdict

from adapters.aws.postgres_build_profile import SharedPostgresBuildProfile
from adapters.database.hosted_migrations import apply_hosted_migrations
from domain.access import LoginSource, Principal, Role
from domain.shared_database import PoolAllocationRequest
from ports.remote_builds import digest, validate_request


def workload_trust(account, region):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account},
                    "ArnLike": {"aws:SourceArn": f"arn:aws:ecs:{region}:{account}:*"},
                },
            }
        ],
    }


class HostedDatabaseBuild:
    def __init__(
        self, policy, allocator, sources, objects, settings, *, security_group, subnets, boundary_arn, session
    ):
        self.policy, self.allocator, self.sources, self.objects, self.settings = (
            policy,
            allocator,
            sources,
            objects,
            settings,
        )
        self.security_group, self.subnets, self.boundary_arn = security_group, tuple(subnets), boundary_arn
        pool = allocator.settings.pool
        if (
            (pool.account_id, pool.region, pool.id, pool.instance_id)
            != (policy.account_id, policy.region, policy.pool_id, policy.instance_id)
            or boundary_arn
            != f"arn:aws:iam::{pool.account_id}:policy/sky-personal-workload-execution-boundary"
        ):
            raise ValueError("Exact registered workload pool and execution boundary required")
        from botocore.config import Config

        config = Config(connect_timeout=5, read_timeout=20, retries={"total_max_attempts": 1})
        self.iam = session.client("iam", region_name=pool.region, config=config)
        self.logs = session.client("logs", region_name=pool.region, config=config)

    @staticmethod
    def key(request):
        artifact, _ = validate_request(request)
        return f"database-preparations/{artifact.organization_id}/{artifact.application_id}/{request['build_id']}.json"

    def _profile(self, request, binding, role_id):
        return SharedPostgresBuildProfile(
            self.allocator,
            binding,
            job_id=request["job_id"],
            security_group=self.security_group,
            subnets=self.subnets,
            execution_role=f"arn:aws:iam::{self.policy.account_id}:role/sky-workload-{request['job_id']}",
            execution_role_id=role_id,
            iam=self.iam,
            logs=self.logs,
        )

    def prepare(self, request, checkpoint, guard, persist):
        import psycopg
        from botocore.exceptions import BotoCoreError, ClientError

        try:
            return self._prepare(request, checkpoint, guard, persist)
        except (BotoCoreError, ClientError, psycopg.Error):
            raise OSError(
                "Database preparation incomplete; exact journaled resources require reconciliation"
            ) from None

    def _prepare(self, request, checkpoint, guard, persist):
        artifact, plan = validate_request(request)
        if plan.get("database_profile") is None:
            return
        self.policy.authorize(request, artifact, plan)
        allocation = PoolAllocationRequest(
            self.allocator.settings.pool, artifact.organization_id, artifact.application_id
        )
        principal = Principal(
            request["created_by"], artifact.organization_id, Role.DEPLOYER, LoginSource.EXTERNAL_IDP
        )
        with self.sources.restore(principal, artifact) as project:
            import hashlib

            from adapters.database.migrations import collect_sql_migrations, trusted_rds_ca_bundle

            bundle = collect_sql_migrations(project)
            ca = project / ".sky-rds-ca.pem"
            if (
                ca.is_symlink()
                or not ca.is_file()
                or hashlib.sha256(ca.read_bytes()).digest()
                != hashlib.sha256(trusted_rds_ca_bundle().read_bytes()).digest()
            ):
                raise ValueError("Approved app must contain the pinned RDS trust bundle")
            # Persist intent before the allocator can create either Secret or DB.
            state = {
                "protocol": "hosted-database-build-v1",
                "request_digest": digest(request),
                "allocation_id": allocation.id,
                "bundle_digest": bundle.digest,
                "stage": "allocating",
            }
            persist({**checkpoint, "database_preparation": state})
            guard()
            self.allocator.allocate(allocation)
            guard()
            registration = self.allocator.inspect_allocation(allocation.binding())
            state = {**state, "stage": "schema", "binding": asdict(allocation.binding())}
            persist({**checkpoint, "database_preparation": state})

            # Credentials live only in this connection closure, not the checkpoint.
            def connect():
                guard()
                credentials = self.allocator._app_credentials(allocation, create=False)
                return self.allocator._connection(
                    registration["host"],
                    registration["port"],
                    allocation.database_name,
                    allocation.login_role,
                    credentials.password,
                )

            schema = apply_hosted_migrations(project, connect, guard=guard)
            state = {**state, "stage": "execution_identity", "schema": schema}
            persist({**checkpoint, "database_preparation": state})
            role_name = "sky-workload-" + request["job_id"]
            tags = {
                "sky-managed": "true",
                "sky-job": request["job_id"],
                "sky-organization": artifact.organization_id,
                "sky-application": artifact.application_id,
            }
            guard()
            # No create retries or update of an existing unverified identity.
            created = self.iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(
                    workload_trust(self.policy.account_id, self.policy.region)
                ),
                PermissionsBoundary=self.boundary_arn,
                Tags=[{"Key": k, "Value": v} for k, v in tags.items()],
            )["Role"]
            guard()
            profile = self._profile(request, allocation.binding(), created["RoleId"])
            if (
                created["Arn"] != profile.role
                or created.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn") != self.boundary_arn
            ):
                raise ValueError("Created workload execution identity differs from approved boundary")
            image_repository = (
                f"{self.policy.account_id}.dkr.ecr.{self.policy.region}.amazonaws.com/sky-managed"
            )
            self.iam.put_role_policy(
                RoleName=role_name,
                PolicyName="SkyWorkloadExecution",
                PolicyDocument=json.dumps(
                    profile.execution_policy(image_repository + "@sha256:" + "0" * 64, registration)
                ),
            )
            guard()
            self.logs.create_log_group(logGroupName=profile.log_group, tags=tags)
            guard()
            self.logs.put_retention_policy(logGroupName=profile.log_group, retentionInDays=7)
            guard()
            receipt = {
                **state,
                "stage": "prepared",
                "role_arn": profile.role,
                "role_id": profile.role_id,
                "execution_boundary_arn": self.boundary_arn,
                "log_group": profile.log_group,
            }
            self.objects.put(self.key(request), receipt)
            guard()
            checkpoint["database_preparation"] = receipt
            persist(checkpoint)

    def for_request(self, request, guard):
        artifact, plan = validate_request(request)
        if plan.get("database_profile") is None:
            return None
        self.policy.authorize(request, artifact, plan)
        guard()
        receipt = self.objects.read(self.key(request))
        allocation = PoolAllocationRequest(
            self.allocator.settings.pool, artifact.organization_id, artifact.application_id
        )
        if (
            receipt.get("protocol") != "hosted-database-build-v1"
            or receipt.get("stage") != "prepared"
            or receipt.get("request_digest") != digest(request)
            or receipt.get("allocation_id") != allocation.id
            or receipt.get("binding") != asdict(allocation.binding())
            or receipt.get("execution_boundary_arn") != self.boundary_arn
            or receipt.get("schema", {}).get("protocol") != "app-role-schema-v1"
        ):
            raise PermissionError("Current immutable DB preparation receipt required")
        profile = self._profile(request, allocation.binding(), receipt["role_id"])
        role = self.iam.get_role(RoleName=profile.role.rsplit("/", 1)[1])["Role"]
        if (
            receipt.get("role_arn") != profile.role
            or receipt.get("log_group") != profile.log_group
            or role.get("RoleId") != profile.role_id
            or role.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn") != self.boundary_arn
        ):
            raise PermissionError("Workload execution identity/boundary changed")
        guard()
        return profile
