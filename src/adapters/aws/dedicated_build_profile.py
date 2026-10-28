"""Existing dedicated target inspection for separately approved promotion.

No role creation, credential rotation, DB allocation or LOGIN change occurs.
An operator/cutover workflow must already own the preparation and copy receipts.
"""

import re
from dataclasses import asdict

from adapters.aws.postgres_build_profile import SharedPostgresBuildProfile
from adapters.database.dedicated_access import PostgresDedicatedAccess, access_identity
from domain.database import DatabaseBinding


class DedicatedPostgresInspector:
    def __init__(self, access, plan, *, operation_id, preparation_receipt):
        self.access, self.plan = access, plan
        self.operation, self.receipt = operation_id, preparation_receipt
        self.settings = access.settings
        self.binding = DatabaseBinding(**plan["target"])
        self.clients = access.preparer.audit.clients

    def inspect_allocation(self, binding):
        if binding != self.binding:
            raise ValueError("Dedicated deployment binding differs from preparation")
        preparer = self.access.preparer
        observed = preparer.observe(self.plan, operation_id=self.operation, guard=lambda: None)
        if observed != self.receipt:
            raise ValueError("Dedicated target preparation evidence changed")
        instance = preparer._describe(binding.instance_id)
        role, marker = access_identity(binding)
        name = "sky-dedicated/" + instance["DbiResourceId"] + "/" + role
        metadata = self.access.client.describe_secret(SecretId=name)
        secret = metadata.get("ARN", "")
        versions = [
            version
            for version, stages in metadata.get("VersionIdsToStages", {}).items()
            if "AWSCURRENT" in stages
        ]
        expected_tags = {
            **preparer._target_tags(self.plan, self.operation, binding),
            "sky-rds-resource-id": instance["DbiResourceId"],
            "sky-access-marker": marker,
        }
        tags = {t["Key"]: t["Value"] for t in metadata.get("Tags", [])}
        prefix = f"arn:aws:secretsmanager:{binding.region}:{binding.account_id}:secret:{name}-"
        if (
            not re.fullmatch(re.escape(prefix) + r"[A-Za-z0-9]{6}", secret)
            or metadata.get("Name") != name
            or metadata.get("DeletedDate")
            or metadata.get("RotationEnabled")
            or metadata.get("OwningService")
            or metadata.get("ReplicationStatus")
            or metadata.get("KmsKeyId") != self.settings.source.app_secret_kms_arn
            or any(tags.get(k) != v for k, v in expected_tags.items())
            or len(versions) != 1
            or not re.fullmatch(r"[A-Za-z0-9-]{32,64}", versions[0])
            or self.access.client.get_resource_policy(SecretId=secret).get("ResourcePolicy")
        ):
            raise ValueError("Dedicated app credential metadata differs from preparation")
        value = preparer.audit._secret_value(secret)
        expected = {
            "username": role,
            "dbname": binding.database_name,
            "host": instance["Endpoint"]["Address"],
            "port": 5432,
            "sslmode": "verify-full",
            "binding": asdict(binding),
            "resource_id": instance["DbiResourceId"],
        }
        if set(value) != set(expected) | {"password"} or any(value.get(k) != v for k, v in expected.items()):
            raise ValueError("Dedicated credential identity changed")
        master = preparer.audit._secret_value(instance["MasterUserSecret"]["SecretArn"])

        def admin():
            return preparer.audit._connection(
                expected["host"], 5432, binding.database_name, "skyadmin", master["password"]
            )

        def login(user, password):
            return preparer.audit._connection(expected["host"], 5432, binding.database_name, user, password)

        PostgresDedicatedAccess(admin, login).existing_access(binding, connection_limit=5, guard=lambda: None)
        with admin() as db:
            db.execute("SET TRANSACTION READ ONLY")
            allowed = db.execute(
                "SELECT datname FROM pg_database WHERE datallowconn AND has_database_privilege(%s,oid,'CONNECT') ORDER BY datname",
                (role,),
            ).fetchall()
            if allowed != [(binding.database_name,)]:
                raise ValueError("Dedicated login can access another database")
        with login(role, value["password"]) as db:
            db.execute("SET TRANSACTION READ ONLY")
            if db.execute("SELECT current_user,current_database()").fetchone() != (
                role,
                binding.database_name,
            ):
                raise ValueError("Dedicated application TLS login could not be verified")
        return {
            "binding": asdict(binding),
            "secret_ref": secret,
            "secret_version": versions[0],
            "login_role": role,
            "host": expected["host"],
            "port": 5432,
            "kms_key_arn": self.settings.source.app_secret_kms_arn,
            "resource_id": instance["DbiResourceId"],
            "tls_verified": True,
            "cross_database_access_denied": True,
        }


class DedicatedPostgresBuildProfile(SharedPostgresBuildProfile):
    DATABASE_ROLE = "dedicated_workload"
    PLAN_PROFILE = "dedicated-postgres-v1"
    PROTOCOL = "dedicated-postgres-deployment-v1"

    @staticmethod
    def registered_scope(allocator):
        target = allocator.binding
        source = allocator.settings.source
        return (
            target.account_id,
            target.region,
            target.instance_id,
            source.vpc_id,
            source.allowed_client_groups,
        )

    def prepare(self, request, result, plan):
        if self.allocator.plan.get("source_revision") != request["source_digest"]:
            raise ValueError("Promotion source revision differs from the immutable build")
        return super().prepare(request, result, plan)
