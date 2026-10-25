"""Deny recorded role incarnations on one original app Secret only.

No Secret values, IAM policy writes, task stops, SQL or candidate policy changes.
An observed resource policy is not proof of propagation or cached credential erasure.
"""

import json
from copy import deepcopy
from types import SimpleNamespace

from adapters.aws.incident_credentials import credential_preparation_principal
from domain.incident_credentials import candidate_resource_policy, candidate_secret_name
from domain.incident_secret_access import (
    IncidentSecretRegistration,
    deny_runtime_secret_policy,
    runtime_secret_policy_matches,
    validate_access_target,
)


def read_policy(raw):
    if raw is None or raw == "":
        return None
    if not isinstance(raw, str) or len(raw.encode()) > 32768:
        raise ValueError("Bounded Secret policy document required")

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate Secret policy field")
            value[key] = item
        return value

    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("Exact Secret policy document required")  # noqa: TRY004 -- invalid registration/policy contract
    return value


class AwsIncidentSecretAccess:
    def __init__(self, registration, *, session=None):
        if not isinstance(registration, IncidentSecretRegistration):
            raise TypeError("Explicit workload Secret registration required")
        if session is None:
            import boto3

            session = boto3.Session(region_name=registration.binding.region)
        from botocore.config import Config

        self.registration = registration
        self.clients = {
            name: session.client(
                name,
                region_name=registration.binding.region,
                config=Config(retries={"total_max_attempts": 1}),
            )
            for name in ("secretsmanager", "ecs", "iam", "sts")
        }

    def _audit(self, context, *, guard):
        r, b = self.registration, self.registration.binding
        from dataclasses import asdict

        if (
            not isinstance(context, dict)
            or set(context)
            != {
                "binding",
                "resource_id",
                "secret_arn",
                "kms_key_arn",
                "candidate_secret_arn",
                "candidate_version_id",
                "preparer_principal",
                "runtime",
            }
            or context["binding"] != asdict(b)
            or context["resource_id"] != r.resource_id
            or context["secret_arn"] != r.secret_arn
            or context["kms_key_arn"] != r.kms_key_arn
        ):
            raise ValueError("Exact registered workload credential context required")

        def call(name, method, **kwargs):
            guard()
            response = getattr(self.clients[name], method)(**kwargs)
            guard()
            return response

        if any(self.clients[name].meta.region_name != b.region for name in ("secretsmanager", "ecs", "sts")):
            raise ValueError("Secret access client region differs from registration")
        guard()
        current = credential_preparation_principal(
            SimpleNamespace(client=lambda name, **_: self.clients[name]), b
        )
        guard()
        if current != context["preparer_principal"]:
            raise ValueError("Only the registered credential preparer may fence Secret access")
        from domain.incident_runtime import runtime_identity

        account, region, _, _, definition, _, _ = runtime_identity(context["runtime"])
        if (account, region) != (b.account_id, b.region):
            raise ValueError("Runtime differs from registered workload account")
        d = call("ecs", "describe_task_definition", taskDefinition=definition)["taskDefinition"]
        containers = d.get("containerDefinitions")
        if (
            d.get("taskDefinitionArn") != definition
            or not isinstance(containers, list)
            or not containers
            or not any(
                isinstance(c, dict)
                and any(
                    isinstance(item, dict)
                    and isinstance(item.get("valueFrom"), str)
                    and (
                        item["valueFrom"] == r.secret_arn or item["valueFrom"].startswith(r.secret_arn + ":")
                    )
                    for item in c.get("secrets", [])
                )
                for c in containers
            )
        ):
            raise ValueError("Recorded definition must reference the registered app Secret")
        arns = {d.get("executionRoleArn")}
        if d.get("taskRoleArn"):
            arns.add(d["taskRoleArn"])
        if any(not isinstance(arn, str) for arn in arns):
            raise ValueError("Recorded task execution role required")
        roles = {}
        for arn in sorted(arns):
            # Validate before deriving a RoleName or making any IAM request.
            validate_access_target(
                {
                    "secret_arn": r.secret_arn,
                    "candidate_secret_arn": context["candidate_secret_arn"],
                    "task_definition_arn": definition,
                    "roles": {arn: "AROA" + "A" * 17},
                },
                context,
            )
            role = call("iam", "get_role", RoleName=arn.rsplit("/", 1)[-1])["Role"]
            if role.get("Arn") != arn or role.get("RoleName") != arn.rsplit("/", 1)[-1]:
                raise ValueError("Runtime role identity changed")
            roles[arn] = role.get("RoleId")
        target = {
            "secret_arn": r.secret_arn,
            "candidate_secret_arn": context["candidate_secret_arn"],
            "task_definition_arn": definition,
            "roles": roles,
        }
        validate_access_target(target, context)

        def metadata(arn, tags):
            m = call("secretsmanager", "describe_secret", SecretId=arn)
            actual = m.get("Tags", [])
            name = arn.split(":secret:", 1)[1][:-7]
            if (
                m.get("ARN") != arn
                or m.get("Name") != name
                or m.get("KmsKeyId") != r.kms_key_arn
                or m.get("DeletedDate")
                or m.get("OwningService")
                or m.get("RotationEnabled")
                or m.get("ReplicationStatus")
                or not isinstance(actual, list)
                or len({t["Key"] for t in actual}) != len(actual)
                or any(
                    {t["Key"]: t["Value"] for t in actual}.get(key) != value for key, value in tags.items()
                )
            ):
                raise ValueError("Secret metadata differs from registered application ownership")
            return m

        metadata(r.secret_arn, r.expected_tags())
        name = candidate_secret_name(r.resource_id, context["candidate_version_id"])
        prefix = f"arn:aws:secretsmanager:{b.region}:{b.account_id}:secret:{name}-"
        import re

        if not re.fullmatch(re.escape(prefix) + r"[A-Za-z0-9]{6}", context["candidate_secret_arn"]):
            raise ValueError("Candidate differs from exact credential preparation")
        candidate = metadata(
            context["candidate_secret_arn"],
            {
                "sky-managed": "true",
                "sky-database-role": "incident_credential",
                "sky-operation-id": context["candidate_version_id"],
                "sky-rds-resource-id": r.resource_id,
                "sky-organization-id": b.organization_id,
                "sky-application-id": b.application_id,
            },
        )
        if candidate.get("VersionIdsToStages") != {context["candidate_version_id"]: ["AWSCURRENT"]}:
            raise ValueError("Exact candidate version required")
        policy = read_policy(
            call("secretsmanager", "get_resource_policy", SecretId=context["candidate_secret_arn"]).get(
                "ResourcePolicy"
            )
        )
        if policy != candidate_resource_policy(context["candidate_secret_arn"], current):
            raise ValueError("Candidate protection differs from registered preparation")
        old_policy = read_policy(
            call("secretsmanager", "get_resource_policy", SecretId=r.secret_arn).get("ResourcePolicy")
        )
        return target, old_policy, call

    def preflight(self, context, *, guard):
        target, old, _ = self._audit(deepcopy(context), guard=guard)
        if old is not None:
            raise ValueError("Existing app Secret policy requires separate operator review")
        return target

    def fence(self, context, target, *, guard):
        validate_access_target(target, context)
        if self.clients["secretsmanager"].meta.config.retries.get("total_max_attempts") != 1:
            raise ValueError("Single-attempt Secret policy mutation client required")
        actual, old, call = self._audit(deepcopy(context), guard=guard)
        if actual != target or old is not None:
            raise ValueError("Runtime roles or existing Secret policy changed after admission")
        call(
            "secretsmanager",
            "put_resource_policy",
            SecretId=target["secret_arn"],
            ResourcePolicy=json.dumps(deny_runtime_secret_policy(target)),
            BlockPublicPolicy=True,
        )
        observed = self.inspect(context, target, guard=guard)
        if observed["policy_state"] != "runtime_roles_denied":
            raise ValueError("Exact runtime Secret deny policy not observed")
        return {
            "target": deepcopy(target),
            "policy_document_verified": True,
            "iam_propagation_verified": False,
            "secret_value_read": False,
            "role_policies_changed": False,
        }

    def inspect(self, context, target, *, guard):
        validate_access_target(target, context)
        actual, policy, _ = self._audit(deepcopy(context), guard=guard)
        if actual != target:
            raise ValueError("Pinned runtime role incarnation changed")
        return {
            "target": deepcopy(target),
            "policy_state": "runtime_roles_denied"
            if runtime_secret_policy_matches(policy, target)
            else "not_recorded"
            if policy is None
            else "review_required",
            "candidate_protected": True,
            "read_only": True,
            "state_changed": False,
            "iam_propagation_verified": False,
            "cached_credentials_erased": False,
            "execution_exclusion_verified": False,
            "recovery_authorized": False,
        }
