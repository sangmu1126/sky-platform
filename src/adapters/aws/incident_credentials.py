"""New isolated candidate Secret + password write; no changes to the old Secret.

Secret creation or SQL uncertainty retains evidence for inspection. The current
runtime is not granted the new Secret and LOGIN is never enabled here.
"""

import json
import re
import secrets
from dataclasses import asdict

from adapters.database.incident_credentials import PostgresIncidentCredentialPreparation
from domain.incident_credentials import candidate_secret_name


def credential_preparation_principal(session, binding):
    """Resolve the actual IAM principal; assumed-role sessions use a stable role ARN."""
    identity = session.client("sts", region_name=binding.region).get_caller_identity()
    if identity.get("Account") != binding.account_id:
        raise ValueError("Credential preparer account differs from registration")
    prefix = f"arn:aws:iam::{binding.account_id}:"
    arn = identity.get("Arn", "")
    if re.fullmatch(re.escape(prefix) + r"user/[A-Za-z0-9+=,.@_/-]{1,512}", arn):
        return arn
    assumed = re.fullmatch(rf"arn:aws:sts::{binding.account_id}:assumed-role/([^/]+)/[^/]+", arn)
    if not assumed:
        raise ValueError("An explicit IAM user or assumed role is required for candidate access")
    role = session.client("iam").get_role(RoleName=assumed[1])["Role"]
    if (
        not re.fullmatch(re.escape(prefix) + r"role/[A-Za-z0-9+=,.@_/-]{1,512}", role.get("Arn", ""))
        or role.get("RoleName") != assumed[1]
        or role.get("RoleId") != identity.get("UserId", "").split(":")[0]
    ):
        raise ValueError("Credential preparer role identity differs from STS")
    return role["Arn"]


class AwsIncidentCredentialPreparation:
    def __init__(self, restriction, *, resource_id, kms_key_arn, principal_arn, client):
        self.sql = PostgresIncidentCredentialPreparation(restriction)
        self.binding, self.resource_id = restriction.binding, resource_id
        candidate_secret_name(resource_id, "a" * 32)
        prefix = f"arn:aws:kms:{self.binding.region}:{self.binding.account_id}:key/"
        if (
            not isinstance(kms_key_arn, str)
            or not re.fullmatch(re.escape(prefix) + r"[a-f0-9-]{36}", kms_key_arn)
            or client.meta.region_name != self.binding.region
        ):
            raise ValueError("Pinned candidate Secret key and region required")
        if not isinstance(principal_arn, str) or not re.fullmatch(
            rf"arn:aws:iam::{self.binding.account_id}:(?:user|role)/[A-Za-z0-9+=,.@_/-]{{1,512}}",
            principal_arn,
        ):
            raise ValueError("Pinned same-account credential preparer principal required")
        self.principal_arn = principal_arn
        self.kms_key_arn, self.client, self.restriction = kms_key_arn, client, restriction

    def prepare(self, operation_id, *, guard):
        name = candidate_secret_name(self.resource_id, operation_id)
        guard()
        observation = self.restriction.inspect(guard=guard)
        if observation["login_enabled"] is not False or observation["active_sessions"] != 0:
            raise ValueError("Current restricted and drained application required")
        password = secrets.token_urlsafe(36)
        identity = {
            "binding": asdict(self.binding),
            "username": self.restriction.fence.role,
            "resource_id": self.resource_id,
            "operation_id": operation_id,
            "sslmode": "verify-full",
        }
        value = {**identity, "password": password}
        tags = {
            "sky-managed": "true",
            "sky-database-role": "incident_credential",
            "sky-operation-id": operation_id,
            "sky-rds-resource-id": self.resource_id,
            "sky-organization-id": self.binding.organization_id,
            "sky-application-id": self.binding.application_id,
        }
        guard()
        # The caller persists intent first. An existing name or uncertain response
        # is never adopted/recreated here; a separate read-only inspection is needed.
        result = self.client.create_secret(
            Name=name,
            ClientRequestToken=operation_id,
            KmsKeyId=self.kms_key_arn,
            SecretString=json.dumps(value),
            Tags=[{"Key": k, "Value": v} for k, v in tags.items()],
        )
        arn = result.get("ARN")
        prefix = f"arn:aws:secretsmanager:{self.binding.region}:{self.binding.account_id}:secret:{name}-"
        if (
            not isinstance(arn, str)
            or not re.fullmatch(re.escape(prefix) + r"[A-Za-z0-9]{6}", arn)
            or result.get("VersionId") != operation_id
        ):
            raise ValueError("Exact candidate Secret creation receipt required")
        guard()
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyUnapprovedIncidentCredentialAccess",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "secretsmanager:*",
                    "Resource": arn,
                    "Condition": {"ArnNotEquals": {"aws:PrincipalArn": self.principal_arn}},
                }
            ],
        }
        self.client.put_resource_policy(
            SecretId=arn, ResourcePolicy=json.dumps(policy), BlockPublicPolicy=True
        )
        guard()
        if json.loads(self.client.get_resource_policy(SecretId=arn).get("ResourcePolicy", "null")) != policy:
            raise ValueError("Candidate Secret must deny access to every unapproved principal")
        metadata = self.client.describe_secret(SecretId=arn)
        actual_tags = metadata.get("Tags", [])
        if (
            metadata.get("ARN") != arn
            or metadata.get("Name") != name
            or metadata.get("KmsKeyId") != self.kms_key_arn
            or metadata.get("DeletedDate")
            or metadata.get("OwningService")
            or metadata.get("RotationEnabled")
            or metadata.get("ReplicationStatus")
            or len({item["Key"] for item in actual_tags}) != len(actual_tags)
            or {item["Key"]: item["Value"] for item in actual_tags} != tags
        ):
            raise ValueError("Candidate Secret identity or access policy differs from intent")
        current = self.client.get_secret_value(
            SecretId=arn, VersionId=operation_id, VersionStage="AWSCURRENT"
        )
        if (
            current.get("ARN") != arn
            or current.get("VersionId") != operation_id
            or "AWSCURRENT" not in current.get("VersionStages", [])
            or json.loads(current["SecretString"]) != value
        ):
            raise ValueError("Exact candidate credential version required")
        guard()
        sql_receipt = self.sql.prepare_password(password, guard=guard)
        guard()
        return {
            **sql_receipt,
            "resource_id": self.resource_id,
            "candidate_secret_ref": arn,
            "candidate_version_id": operation_id,
            "runtime_access_granted": False,
            "candidate_access_principal": self.principal_arn,
        }
