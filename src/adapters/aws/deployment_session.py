"""Lease-bound, per-operation AWS deployment credentials; no ambient fallback.

The broker role is operator provisioned with a mandatory boundary. Its policy
uses the authenticated control plane's session tags, while an STS inline policy
also fixes the exact service/family. No credential enters application code.
"""

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from adapters.aws.delegated_session import ScopedAppSession
from ports.remote_builds import validate_request


@dataclass(frozen=True)
class DeploymentRoleRegistration:
    account_id: str
    region: str
    source_role_arn: str
    role_arn: str
    role_id: str
    boundary_arn: str
    core_stack_arn: str
    execution_role_arn: str
    infrastructure_role_arn: str
    external_id: str
    expires_at: str

    def __post_init__(self):
        if not re.fullmatch(r"[0-9]{12}", self.account_id) or not re.fullmatch(
            r"[a-z]{2}(?:-[a-z]+)+-\d+", self.region
        ):
            raise ValueError("Exact deployment account/region required")
        prefix = "arn:aws:iam::" + self.account_id + ":"
        for value in (self.source_role_arn, self.role_arn):
            if not re.fullmatch(re.escape(prefix) + r"role/sky-[A-Za-z0-9_-]+", value):
                raise ValueError("Pinned same-account deployment roles required")
        if not re.fullmatch(r"AROA[A-Z0-9]{17}", self.role_id) or not re.fullmatch(
            re.escape(prefix) + r"policy/sky-[A-Za-z0-9_-]+", self.boundary_arn
        ):
            raise ValueError("Immutable broker identity and boundary required")
        for value, name in (
            (self.execution_role_arn, "ExecutionRole"),
            (self.infrastructure_role_arn, "InfrastructureRole"),
        ):
            if not re.fullmatch(re.escape(prefix) + r"role/sky-core-" + name + r"-[A-Za-z0-9]+", value):
                raise ValueError("Only registered core roles may be passed")
        if not re.fullmatch(
            rf"arn:aws:cloudformation:{self.region}:{self.account_id}:stack/sky-core/[A-Za-z0-9-]+",
            self.core_stack_arn,
        ):
            raise ValueError("Exact owned core stack required")
        if not re.fullmatch(r"[A-Za-z0-9_:-]{32,128}", self.external_id):
            raise ValueError("Operator deputy binding required")
        if datetime.fromisoformat(self.expires_at).tzinfo is None:
            raise ValueError("Timezone-aware bounded registration required")

    @classmethod
    def load(cls, value):
        if not isinstance(value, str) or len(value) > 8192:
            raise ValueError("Trusted deployment role registration required")
        return cls(**json.loads(value))


def deployment_policy(registration, request, *, database_role=None):
    artifact, _ = validate_request(request)
    r = registration
    if (request["account_id"], request["region"]) != (r.account_id, r.region):
        raise PermissionError("Deployment request differs from registered destination")
    base = f"arn:aws:ecs:{r.region}:{r.account_id}:"
    token = request["build_id"].replace("-", "")
    resources = [
        base + "service/default/sky-b-" + token,
        base + "service-deployment/default/sky-b-" + token + "/*",
        base + "task-definition/default-sky-b-" + token + ":*",
        base + "cluster/default",
        r.core_stack_arn,
        r.execution_role_arn,
        r.infrastructure_role_arn,
    ]
    if database_role is not None:
        if database_role != f"arn:aws:iam::{r.account_id}:role/sky-workload-{request['job_id']}":
            raise PermissionError("Database execution role differs from this admitted job")
        resources.append(database_role)
    actions = [
        "ecs:CreateExpressGatewayService",
        "ecs:DescribeExpressGatewayService",
        "ecs:DeleteExpressGatewayService",
        "ecs:DescribeServiceDeployments",
        "ecs:ListTagsForResource",
        "ecs:TagResource",
        "ecs:RegisterTaskDefinition",
        "ecs:CreateCluster",
        "iam:PassRole",
        "cloudformation:DescribeStacks",
    ]
    if database_role is not None:
        resources.append(base + "task/default/*")  # Read-only task inventory; SDK callbacks bind the service.
        actions.append("ecs:DescribeTasks")
    metadata_actions = ["ecs:DescribeTaskDefinition", "sts:GetCallerIdentity"]
    if database_role is not None:
        metadata_actions.append("ecs:ListTasks")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": actions, "Resource": resources},
            # DescribeTaskDefinition is an AWS metadata action without resource scoping.
            {"Effect": "Allow", "Action": ["ecs:DescribeTaskDefinition"], "Resource": "*"},
            {
                "Effect": "Deny",
                "NotAction": metadata_actions,
                "NotResource": resources,
            },
            {
                "Effect": "Deny",
                "NotAction": [*actions, *metadata_actions],
                "Resource": "*",
            },
        ],
    }
    if database_role is not None:
        policy["Statement"].append(
            {
                "Effect": "Allow",
                "Action": ["ecs:ListTasks"],
                "Resource": "*",
                "Condition": {"ArnEquals": {"ecs:cluster": base + "cluster/default"}},
            }
        )
    # IAM still intersects this session with the broker boundary/role policy.
    text = json.dumps(policy, separators=(",", ":"))
    if len(text) > 2048:
        # NotResource is the actual restriction; let the boundary supply the allow-list.
        policy["Statement"][0] = {"Effect": "Allow", "Action": actions, "Resource": "*"}
        text = json.dumps(policy, separators=(",", ":"))
    if len(text) > 2048:
        raise ValueError("Deployment session exceeds STS policy limit")
    return text, artifact


class ScopedDeploymentFactory:
    def __init__(
        self,
        settings,
        registration,
        *,
        source=None,
        database_profile=None,
        database_resolver=None,
        clock=lambda: datetime.now(UTC),
    ):
        if not isinstance(registration, DeploymentRoleRegistration):
            raise TypeError("Trusted deployment registration required")
        self.database_resolver = database_resolver
        if database_profile is not None and database_resolver is not None:
            raise ValueError("Use a fixed database profile or an immutable request resolver")
        self.settings, self.registration, self.database_profile, self.clock = (
            settings,
            registration,
            database_profile,
            clock,
        )
        if (settings.account_id, settings.region) != (registration.account_id, registration.region):
            raise ValueError("Worker and delegation destination differ")
        if source is None:
            import boto3

            source = boto3.Session(region_name=registration.region)
        self.source = source

    def for_request(self, request, guard):
        from botocore.config import Config

        from adapters.aws.built_deployment import BuiltImageDeployment

        r = self.registration
        now = self.clock()
        expiry = datetime.fromisoformat(r.expires_at)
        if now.tzinfo is None or not now < expiry <= now + timedelta(days=1):
            raise PermissionError("Deployment registration expired or outside approved interval")
        profile = (
            self.database_resolver.for_request(request, guard)
            if self.database_resolver is not None
            else self.database_profile
        )
        policy, artifact = deployment_policy(r, request, database_role=getattr(profile, "role", None))
        if profile is not None and (
            profile.job != request["job_id"]
            or profile.binding.organization_id != artifact.organization_id
            or profile.binding.application_id != artifact.application_id
        ):
            raise PermissionError("Database role registration belongs to another application")
        guard()
        sts = self.source.client("sts", region_name=r.region)
        source = sts.get_caller_identity()
        expected = f"arn:aws:sts::{r.account_id}:assumed-role/{r.source_role_arn.rsplit('/', 1)[1]}/"
        if source.get("Account") != r.account_id or not source.get("Arn", "").startswith(expected):
            raise PermissionError("Only the registered hosted worker may delegate deployments")
        role = self.source.client("iam", region_name=r.region).get_role(
            RoleName=r.role_arn.rsplit("/", 1)[1]
        )["Role"]
        if (
            role.get("Arn") != r.role_arn
            or role.get("RoleId") != r.role_id
            or role.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn") != r.boundary_arn
        ):
            raise PermissionError("Deployment broker identity/boundary changed")
        guard()
        response = sts.assume_role(
            RoleArn=r.role_arn,
            RoleSessionName="sky-deploy-" + request["job_id"],
            ExternalId=r.external_id,
            DurationSeconds=900,
            Policy=policy,
            Tags=[
                {"Key": k, "Value": v}
                for k, v in {
                    "sky:OrganizationId": artifact.organization_id,
                    "sky:ApplicationId": artifact.application_id,
                    "sky:DeploymentToken": request["build_id"].replace("-", ""),
                    "sky:JobId": request["job_id"],
                    "sky:Workspace": request["workspace"],
                }.items()
            ],
        )
        guard()
        creds = response["Credentials"]
        issued = self.clock()
        end = creds["Expiration"]
        if (
            not response["AssumedRoleUser"]["AssumedRoleId"].startswith(r.role_id + ":")
            or not isinstance(end, datetime)
            or end.tzinfo is None
            or not issued < end <= issued + timedelta(seconds=901)
            or issued >= expiry
        ):
            raise PermissionError("Issued deployment credentials differ from registration")
        import boto3

        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=r.region,
        )
        scoped = ScopedAppSession(
            session,
            SimpleNamespace(region=r.region, expires_at=r.expires_at),
            min(end, expiry),
            guard,
            self.clock,
        )
        config = Config(connect_timeout=5, read_timeout=20, retries={"total_max_attempts": 1})
        ecs = scoped.client("ecs", config=config)

        def metadata_scope(params, **_):
            guard()
            family = "default-sky-b-" + request["build_id"].replace("-", "")
            value = params.get("taskDefinition", "")
            prefix = f"arn:aws:ecs:{r.region}:{r.account_id}:task-definition/"
            if not re.fullmatch(re.escape(prefix + family) + r":[1-9][0-9]*", value):
                raise PermissionError("Task metadata belongs to another deployment")

        ecs.meta.events.register("before-parameter-build.ecs.DescribeTaskDefinition", metadata_scope)
        if profile is not None:
            expected_service = "sky-b-" + request["build_id"].replace("-", "")
            tasks = set()

            def list_scope(params, **_):
                guard()
                if (
                    params.get("cluster") != "default"
                    or params.get("serviceName") != expected_service
                    or params.get("desiredStatus") != "RUNNING"
                    or params.get("nextToken")
                ):
                    raise PermissionError("Task inventory differs from this deployment")

            def listed(parsed, **_):
                guard()
                arns = parsed.get("taskArns", [])
                prefix = f"arn:aws:ecs:{r.region}:{r.account_id}:task/default/"
                if (
                    parsed.get("nextToken")
                    or not isinstance(arns, list)
                    or len(arns) > 1
                    or any(
                        not isinstance(a, str) or not re.fullmatch(re.escape(prefix) + r"[0-9a-f]{32}", a)
                        for a in arns
                    )
                ):
                    raise PermissionError("Unambiguous registered service task inventory required")
                tasks.clear()
                tasks.update(arns)

            def describe_scope(params, **_):
                guard()
                if (
                    params.get("cluster") != "default"
                    or not tasks
                    or set(params.get("tasks", [])) != tasks
                    or len(params["tasks"]) != len(tasks)
                ):
                    raise PermissionError("Task metadata differs from the exact service inventory")

            ecs.meta.events.register("before-parameter-build.ecs.ListTasks", list_scope)
            ecs.meta.events.register("after-call.ecs.ListTasks", listed)
            ecs.meta.events.register("before-parameter-build.ecs.DescribeTasks", describe_scope)
        return BuiltImageDeployment(
            self.settings,
            ecs=ecs,
            stacks=scoped.client("cloudformation", config=config),
            identity=scoped.client("sts", config=config),
            database_profile=profile,
        )
