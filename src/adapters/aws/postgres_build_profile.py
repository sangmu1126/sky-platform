"""Read-only binding of an existing shared allocation to one verified build.

Registration comes from the operator, never the uploaded app or AI output.
Allocation, schema/data preparation and cost consent precede this boundary.
It creates no database, credential or IAM role and runs no uploaded code.
"""

import re
from dataclasses import asdict

from domain.database import DatabaseBinding
from ports.remote_builds import validate_request


def verify_postgres_task(ecs, intent, definition):
    """Require the actual single task, including pinned credentials and network."""
    name = intent["payload"]["serviceName"]
    listed = ecs.list_tasks(cluster="default", serviceName=name, desiredStatus="RUNNING", maxResults=100)
    if listed.get("nextToken") or len(listed.get("taskArns", [])) != 1:
        raise ValueError("One running PostgreSQL application task required")
    described = ecs.describe_tasks(cluster="default", tasks=listed["taskArns"])
    tasks = described.get("tasks", [])
    if described.get("failures") or len(tasks) != 1:
        raise ValueError("PostgreSQL application task could not be verified")
    task = tasks[0]
    containers = task.get("containers", [])
    if (
        task.get("taskArn") != listed["taskArns"][0]
        or task.get("taskDefinitionArn") != definition
        or task.get("group") != "service:" + name
        or task.get("lastStatus") != "RUNNING"
        or task.get("desiredStatus") != "RUNNING"
        or len(containers) != 1
        or containers[0].get("name") != "Main"
        or containers[0].get("imageDigest") != intent["image"].split("@")[1]
    ):
        raise ValueError("Actual PostgreSQL task image differs from the verified build")
    spec = ecs.describe_task_definition(taskDefinition=definition)["taskDefinition"]
    actual = spec.get("containerDefinitions", [])
    expected = intent["payload"]["primaryContainer"]
    if (
        len(actual) != 1
        or actual[0].get("name") != "Main"
        or actual[0].get("image") != intent["image"]
        or sorted(actual[0].get("environment", []), key=lambda x: x["name"])
        != sorted(expected["environment"], key=lambda x: x["name"])
        or sorted(actual[0].get("secrets", []), key=lambda x: x["name"])
        != sorted(expected["secrets"], key=lambda x: x["name"])
        or spec.get("executionRoleArn") != intent["payload"]["executionRoleArn"]
        or spec.get("taskRoleArn")
        or spec.get("volumes")
    ):
        raise ValueError("Actual PostgreSQL credentials or execution configuration changed")
    return {
        "protocol": "ecs-image-identity-v1",
        "status": "passed",
        "service_arn": intent["service_arn"],
        "task_definition_arn": definition,
        "task_arns": listed["taskArns"],
    }


class SharedPostgresBuildProfile:
    ENVIRONMENT = frozenset(
        {"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGSSLMODE", "PGSSLROOTCERT"}
    )

    def __init__(
        self,
        allocator,
        binding,
        *,
        job_id,
        security_group,
        subnets,
        execution_role,
        execution_role_id,
        iam,
        logs=None,
    ):
        if not isinstance(binding, DatabaseBinding) or binding.role != "shared_workload":
            raise ValueError("Existing shared workload binding required")
        if (
            not re.fullmatch(r"[a-f0-9]{16}", job_id)
            or not re.fullmatch(r"sg-[a-f0-9]{8,17}", security_group)
            or not re.fullmatch(
                rf"arn:aws:iam::{binding.account_id}:role/sky-workload-[A-Za-z0-9_-]+", execution_role
            )
            or not re.fullmatch(r"AROA[A-Z0-9]{17}", execution_role_id)
            or security_group not in allocator.settings.allowed_client_groups
            or not isinstance(subnets, tuple)
            or not 2 <= len(subnets) <= 3
            or len(set(subnets)) != len(subnets)
            or any(not re.fullmatch(r"subnet-[a-f0-9]{8,17}", value) for value in subnets)
            or allocator.settings.pool.account_id != binding.account_id
            or allocator.settings.pool.region != binding.region
            or allocator.settings.pool.instance_id != binding.instance_id
        ):
            raise ValueError("Pinned workload execution registration required")
        self.allocator, self.binding, self.job = allocator, binding, job_id
        self.group, self.role, self.role_id, self.iam = security_group, execution_role, execution_role_id, iam
        self.subnets = subnets
        self.logs = logs
        self.log_group = f"/sky/workloads/{binding.organization_id}/{binding.application_id}/{job_id}"

    def execution_policy(self, image, registration):
        account, region = self.binding.account_id, self.binding.region
        repository = image.split("@")[0].split("amazonaws.com/", 1)[1]
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": f"arn:aws:logs:{region}:{account}:log-group:{self.log_group}:log-stream:app/*",
                },
                {"Effect": "Allow", "Action": ["ecr:GetAuthorizationToken"], "Resource": "*"},
                {
                    "Effect": "Allow",
                    "Action": [
                        "ecr:BatchCheckLayerAvailability",
                        "ecr:GetDownloadUrlForLayer",
                        "ecr:BatchGetImage",
                    ],
                    "Resource": f"arn:aws:ecr:{region}:{account}:repository/{repository}",
                },
                {
                    "Effect": "Allow",
                    "Action": ["secretsmanager:GetSecretValue"],
                    "Resource": registration["secret_ref"],
                },
                {
                    "Effect": "Allow",
                    "Action": ["kms:Decrypt"],
                    "Resource": registration["kms_key_arn"],
                    "Condition": {
                        "StringEquals": {
                            "kms:ViaService": f"secretsmanager.{region}.amazonaws.com",
                            "kms:EncryptionContext:SecretARN": registration["secret_ref"],
                        }
                    },
                },
            ],
        }

    def _audit_role(self, image, registration):
        name = self.role.rsplit("/", 1)[1]
        role = self.iam.get_role(RoleName=name)["Role"]
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": self.binding.account_id},
                        "ArnLike": {
                            "aws:SourceArn": f"arn:aws:ecs:{self.binding.region}:{self.binding.account_id}:*"
                        },
                    },
                }
            ],
        }
        tags = {t["Key"]: t["Value"] for t in role.get("Tags", [])}
        if (
            role.get("Arn") != self.role
            or role.get("RoleId") != self.role_id
            or role.get("AssumeRolePolicyDocument") != trust
            or any(
                tags.get(k) != v
                for k, v in {
                    "sky-managed": "true",
                    "sky-job": self.job,
                    "sky-application": self.binding.application_id,
                    "sky-organization": self.binding.organization_id,
                }.items()
            )
        ):
            raise ValueError("Workload execution role incarnation, trust or ownership changed")
        attached = self.iam.list_attached_role_policies(RoleName=name)
        inline = self.iam.list_role_policies(RoleName=name)
        if (
            attached.get("IsTruncated")
            or attached.get("AttachedPolicies") != []
            or inline.get("IsTruncated")
            or inline.get("PolicyNames") != ["SkyWorkloadExecution"]
            or self.iam.get_role_policy(RoleName=name, PolicyName="SkyWorkloadExecution")["PolicyDocument"]
            != self.execution_policy(image, registration)
        ):
            raise ValueError("Workload execution role exceeds registered minimum")

    def prepare(self, request, result, plan):
        source, _ = validate_request(request)
        profile = plan.get("infrastructure_profile", {})
        requirements = profile.get("requirements") if isinstance(profile, dict) else None
        if (
            (
                source.organization_id,
                source.application_id,
                request["job_id"],
                request["account_id"],
                request["region"],
            )
            != (
                self.binding.organization_id,
                self.binding.application_id,
                self.job,
                self.binding.account_id,
                self.binding.region,
            )
            or plan.get("database_profile") != "shared-postgres-v1"
            or not isinstance(requirements, list)
            or set(requirements) != {"database"}
            or profile.get("database_engines") != ["postgresql"]
            or not isinstance(plan.get("required_env"), list)
            or set(plan["required_env"]) - self.ENVIRONMENT
        ):
            raise ValueError("Build requires unsupported or differently owned workload resources")
        registration = self.allocator.inspect_allocation(self.binding)
        if self.logs is None:
            raise ValueError("Registered workload log client required")
        groups = self.logs.describe_log_groups(logGroupNamePrefix=self.log_group)
        exact = [g for g in groups.get("logGroups", []) if g.get("logGroupName") == self.log_group]
        if groups.get("nextToken") or len(exact) != 1 or exact[0].get("retentionInDays") != 7:
            raise ValueError("Existing bounded workload log group required")
        tags = self.logs.list_tags_log_group(logGroupName=self.log_group).get("tags", {})
        if any(
            tags.get(k) != v
            for k, v in {
                "sky-managed": "true",
                "sky-job": self.job,
                "sky-organization": self.binding.organization_id,
                "sky-application": self.binding.application_id,
            }.items()
        ):
            raise ValueError("Workload log ownership changed")
        described = self.allocator.clients["ec2"].describe_subnets(SubnetIds=list(self.subnets))
        values = described.get("Subnets", [])
        if (
            described.get("NextToken")
            or {v.get("SubnetId") for v in values} != set(self.subnets)
            or len(values) != len(self.subnets)
            or len({v.get("AvailabilityZone") for v in values}) < 2
            or any(
                v.get("VpcId") != self.allocator.settings.vpc_id
                or v.get("OwnerId") != self.binding.account_id
                or v.get("State") != "available"
                for v in values
            )
        ):
            raise ValueError("Registered workload multi-AZ subnet ownership changed")
        self._audit_role(result["image"], registration)
        return registration

    def payload(self, registration):
        environment = {
            "PGHOST": registration["host"],
            "PGPORT": str(registration["port"]),
            "PGDATABASE": self.binding.database_name,
            "PGSSLMODE": "verify-full",
            "PGSSLROOTCERT": "/app/.sky-rds-ca.pem",
        }
        return {
            "executionRoleArn": self.role,
            "networkConfiguration": {"securityGroups": [self.group], "subnets": list(self.subnets)},
            "awsLogsConfiguration": {"logGroup": self.log_group, "logStreamPrefix": "app"},
            "environment": [{"name": key, "value": value} for key, value in environment.items()],
            "secrets": [
                {
                    "name": name,
                    "valueFrom": registration["secret_ref"]
                    + ":"
                    + field
                    + "::"
                    + registration["secret_version"],
                }
                for name, field in [("PGUSER", "username"), ("PGPASSWORD", "password")]
            ],
        }

    def verify(self, intent):
        registration = self.allocator.inspect_allocation(self.binding)
        if registration != intent["database_registration"]:
            raise ValueError("Database, credentials or ownership changed after deployment intent")
        self._audit_role(intent["image"], registration)
        return {
            "binding": asdict(self.binding),
            "secret_ref": registration["secret_ref"],
            "secret_version": registration["secret_version"],
            "protocol": "shared-postgres-deployment-v1",
            "tls_verified": True,
            "cross_database_access_denied": True,
        }
