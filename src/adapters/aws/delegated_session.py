"""Operator-registered same-account app sessions; credentials never enter user code.

Registration is trusted control-plane configuration, not an upload/AI proposal.
Session permissions intersect the role boundary and role permissions. This
profile deliberately does not implement customer cross-account onboarding.
"""

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

_ACTIONS = frozenset(
    {
        "kms:Decrypt",
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret",
        "s3:GetObject",
        "s3:PutObject",
        "ecs:DescribeExpressGatewayService",
        "ecs:CreateExpressGatewayService",
        "ecs:DescribeServices",
        "ecs:DescribeServiceDeployments",
        "ecs:ListTagsForResource",
        "ecs:TagResource",
        "ecs:RegisterTaskDefinition",
        "cloudformation:DescribeStacks",
        "cloudformation:DescribeStackResources",
        "cloudformation:CreateStack",
        "cloudformation:DeleteStack",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer",
    }
)


@dataclass(frozen=True)
class AppRoleRegistration:
    organization_id: str
    application_id: str
    account_id: str
    region: str
    source_principal_arn: str
    role_arn: str
    role_id: str
    external_id: str
    expires_at: str
    statements_json: str
    boundary_arn: str

    def __post_init__(self):
        if any(
            not isinstance(x, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", x)
            for x in (self.organization_id, self.application_id)
        ):
            raise ValueError("Exact registered tenant/application required")
        if not re.fullmatch(r"[0-9]{12}", self.account_id) or not re.fullmatch(
            r"[a-z]{2}(?:-[a-z]+)+-\d+", self.region
        ):
            raise ValueError("Registered account/region required")
        prefix = "arn:aws:iam::" + self.account_id + ":"
        if (
            not self.source_principal_arn.startswith(prefix)
            or not re.fullmatch(
                re.escape(prefix) + r"(?:user|role)/[A-Za-z0-9+=,.@_/-]+", self.source_principal_arn
            )
            or not re.fullmatch(re.escape(prefix) + r"role/sky-[a-z0-9-]+", self.role_arn)
            or not re.fullmatch(r"AROA[A-Z0-9]{17}", self.role_id)
            or not re.fullmatch(r"[A-Za-z0-9_:-]{32,128}", self.external_id)
        ):
            raise ValueError("Pinned same-account source and immutable app role required")
        expiry = datetime.fromisoformat(self.expires_at)
        if expiry.tzinfo is None:
            raise ValueError("Timezone-aware registration expiry required")
        if not re.fullmatch(re.escape(prefix) + r"policy/sky-[a-z0-9-]+", self.boundary_arn):
            raise ValueError("An exact owned permissions boundary is required")
        if len(self.statements_json) > 16384:
            raise ValueError("Bounded app permissions required")
        statements = json.loads(self.statements_json)
        if not isinstance(statements, list) or not 1 <= len(statements) <= 16:
            raise ValueError("Bounded app permissions required")
        for statement in statements:
            if (
                not isinstance(statement, dict)
                or set(statement)
                not in ({"Effect", "Action", "Resource"}, {"Effect", "Action", "Resource", "Condition"})
                or statement["Effect"] != "Allow"
                or not isinstance(statement["Action"], list)
                or not statement["Action"]
                or not set(statement["Action"]) <= _ACTIONS
                or not isinstance(statement["Resource"], list)
                or not statement["Resource"]
            ):
                raise ValueError("Explicit supported app permissions required")
            if "kms:Decrypt" in statement["Action"]:
                own = {
                    resource
                    for item in statements
                    if "secretsmanager:GetSecretValue" in item.get("Action", [])
                    for resource in item.get("Resource", [])
                }
                expected = {
                    "StringEquals": {
                        "kms:ViaService": "secretsmanager." + self.region + ".amazonaws.com",
                        "kms:EncryptionContext:SecretARN": sorted(own),
                    }
                }
                if (
                    statement["Action"] != ["kms:Decrypt"]
                    or not own
                    or statement.get("Condition") != expected
                    or len(statement["Resource"]) != 1
                    or not re.fullmatch(
                        "arn:aws:kms:"
                        + re.escape(self.region)
                        + ":"
                        + self.account_id
                        + r":key/[a-f0-9-]{36}",
                        statement["Resource"][0],
                    )
                ):
                    raise ValueError(
                        "KMS decryption requires the exact key, Secret context and Secrets Manager path"
                    )
            elif "Condition" in statement:
                raise ValueError("Unexpected delegated permission condition")
            for resource in statement["Resource"]:
                if (
                    not isinstance(resource, str)
                    or len(resource) > 512
                    or "?" in resource
                    or "*" in resource.removesuffix("/*")
                    or not resource.startswith("arn:aws:")
                    or (
                        resource.split(":")[2] != "s3"
                        and resource.split(":")[3:5] != [self.region, self.account_id]
                    )
                ):
                    raise ValueError("App resources must be bounded and in the registered account/region")
        policy = self.policy()
        if len(policy) > 2048:
            raise ValueError("STS session policy exceeds bound")

    def policy(self):
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    *json.loads(self.statements_json),
                    {
                        "Effect": "Deny",
                        "NotAction": ["sts:GetCallerIdentity"],
                        "NotResource": sorted(
                            {
                                resource
                                for item in json.loads(self.statements_json)
                                for resource in item["Resource"]
                            }
                        ),
                    },
                    {
                        "Effect": "Deny",
                        "NotAction": sorted(
                            {
                                "sts:GetCallerIdentity",
                                *(
                                    action
                                    for item in json.loads(self.statements_json)
                                    for action in item["Action"]
                                ),
                            }
                        ),
                        "Resource": "*",
                    },
                    {
                        "Effect": "Deny",
                        "NotAction": ["sts:GetCallerIdentity"],
                        "Resource": "*",
                        "Condition": {"StringNotEquals": {"aws:RequestedRegion": self.region}},
                    },
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        )


class ScopedAppSession:
    def __init__(self, session, registration, expiry, guard, clock):
        self._session, self.registration, self.expiry, self.guard, self.clock = (
            session,
            registration,
            expiry,
            guard,
            clock,
        )

    def check(self, **_):
        self.guard()
        now = self.clock()
        if (
            now.tzinfo is None
            or now >= self.expiry
            or now >= datetime.fromisoformat(self.registration.expires_at)
        ):
            raise PermissionError("App delegation expired; do not reuse credentials")

    def client(self, name, *, region_name=None, **kwargs):
        self.check()
        if region_name is not None and region_name != self.registration.region:
            raise PermissionError("Delegated region differs from the registered application")
        if set(kwargs) - {"config"}:
            raise ValueError("Delegated clients cannot override credentials, TLS or endpoints")
        client = self._session.client(name, region_name=self.registration.region, **kwargs)
        client.meta.events.register("before-call.*.*", self.check)
        client.meta.events.register("after-call.*.*", self.check)
        return client


def assume_app_session(
    registration, source_session, *, organization_id, application_id, guard, clock=lambda: datetime.now(UTC)
):
    if not isinstance(registration, AppRoleRegistration) or not callable(guard):
        raise TypeError("Trusted app role registration and execution guard required")
    if (organization_id, application_id) != (registration.organization_id, registration.application_id):
        raise PermissionError("Delegation belongs to another tenant/application")
    now = clock()
    expiry = datetime.fromisoformat(registration.expires_at)
    if now.tzinfo is None or not now < expiry <= now + timedelta(days=1):
        raise PermissionError("App delegation registration is expired or outside its bounded approval")
    guard()
    sts = source_session.client("sts", region_name=registration.region)
    source = sts.get_caller_identity()
    arn = source.get("Arn", "")
    if ":assumed-role/" in arn:
        arn = (
            "arn:aws:iam::"
            + source["Account"]
            + ":role/"
            + arn.split(":assumed-role/", 1)[1].rsplit("/", 1)[0]
        )
    if source.get("Account") != registration.account_id or arn != registration.source_principal_arn:
        raise PermissionError("Delegation source identity differs from trusted registration")
    role = source_session.client("iam", region_name=registration.region).get_role(
        RoleName=registration.role_arn.rsplit("/", 1)[1]
    )["Role"]
    if (
        role.get("RoleId") != registration.role_id
        or role.get("Arn") != registration.role_arn
        or role.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn") != registration.boundary_arn
    ):
        raise PermissionError("Current role identity or permissions boundary differs from registration")
    guard()
    response = sts.assume_role(
        RoleArn=registration.role_arn,
        RoleSessionName="sky-app-" + uuid4().hex[:16],
        ExternalId=registration.external_id,
        DurationSeconds=900,
        Policy=registration.policy(),
        Tags=[
            {"Key": "sky:OrganizationId", "Value": organization_id},
            {"Key": "sky:ApplicationId", "Value": application_id},
        ],
    )
    guard()
    assumed = response["AssumedRoleUser"]
    creds = response["Credentials"]
    end = creds["Expiration"]
    issued_at = clock()
    if (
        not isinstance(end, datetime)
        or end.tzinfo is None
        or issued_at.tzinfo is None
        or not assumed["AssumedRoleId"].startswith(registration.role_id + ":")
        or not assumed["Arn"].startswith(
            "arn:aws:sts::"
            + registration.account_id
            + ":assumed-role/"
            + registration.role_arn.rsplit("/", 1)[1]
            + "/"
        )
        or not issued_at < end <= issued_at + timedelta(seconds=901)
        or issued_at >= expiry
    ):
        raise PermissionError("Issued credentials differ from pinned role identity or lifetime")
    import boto3

    session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=registration.region,
    )
    return ScopedAppSession(session, registration, min(end, expiry), guard, clock)
