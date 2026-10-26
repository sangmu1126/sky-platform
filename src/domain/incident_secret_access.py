"""Pin one workload Secret and the recorded runtime roles, never whole shared roles."""

import hashlib
import json
import re
from dataclasses import asdict, dataclass

from domain.database import DatabaseBinding
from domain.incident_credentials import candidate_secret_name
from domain.incident_runtime import runtime_identity


@dataclass(frozen=True)
class IncidentSecretRegistration:
    binding: DatabaseBinding
    resource_id: str
    secret_arn: str
    kms_key_arn: str

    def __post_init__(self):
        b = self.binding
        if not isinstance(b, DatabaseBinding) or b.role not in {"shared_workload", "dedicated_workload"}:
            raise ValueError("Registered workload database required")
        candidate_secret_name(self.resource_id, "a" * 32)
        prefix = f"arn:aws:secretsmanager:{b.region}:{b.account_id}:secret:"
        if not isinstance(self.secret_arn, str) or not self.secret_arn.startswith(prefix):
            raise ValueError("Pinned same-account workload Secret required")
        if not isinstance(self.kms_key_arn, str) or not re.fullmatch(
            re.escape(f"arn:aws:kms:{b.region}:{b.account_id}:key/") + r"[a-f0-9-]{36}", self.kms_key_arn
        ):
            raise ValueError("Pinned workload Secret KMS key required")
        name = self.secret_arn.removeprefix(prefix)
        if b.role == "shared_workload":
            allocation = re.fullmatch(r"allocation-([a-f0-9]{24})", b.owner_ref)
            match = re.fullmatch(
                r"sky-pool/([A-Za-z0-9][A-Za-z0-9_-]{0,127})/([a-f0-9]{24})-[A-Za-z0-9]{6}", name
            )
            if not allocation or not match or allocation[1] != match[2]:
                raise ValueError("Secret differs from registered shared allocation")
        else:
            digest = hashlib.sha256(json.dumps(asdict(b), sort_keys=True).encode()).hexdigest()[:24]
            expected = "sky-dedicated/" + self.resource_id + "/sky_dedicated_" + digest
            if not re.fullmatch(re.escape(expected) + r"-[A-Za-z0-9]{6}", name):
                raise ValueError("Secret differs from registered dedicated access")

    def expected_tags(self):
        b = self.binding
        tags = {
            "sky-managed": "true",
            "sky-database-role": b.role,
            "sky-organization-id": b.organization_id,
            "sky-application-id": b.application_id,
            "sky-rds-resource-id": self.resource_id,
        }
        if b.role == "shared_workload":
            name = self.secret_arn.split(":secret:", 1)[1]
            tags.update(
                {
                    "sky-pool-id": name.split("/")[1],
                    "sky-allocation-id": b.owner_ref.removeprefix("allocation-"),
                }
            )
        else:
            digest = hashlib.sha256(json.dumps(asdict(b), sort_keys=True).encode()).hexdigest()[:24]
            tags.update(
                {"sky-owner-ref": b.owner_ref, "sky-access-marker": "sky-dedicated-access-v1:" + digest}
            )
        return tags


def runtime_context(result):
    runtime_identity(result)
    return {
        **{
            key: result[key]
            for key in ("account", "region", "target", "owner_attempt", "service", "task_definition_arn")
        },
        "image_identity": {
            key: result["image_identity"][key]
            for key in ("protocol", "status", "service_arn", "task_definition_arn", "task_arns")
        },
    }


def validate_access_target(target, context):
    if (
        not isinstance(target, dict)
        or set(target) != {"secret_arn", "candidate_secret_arn", "task_definition_arn", "roles"}
        or target["secret_arn"] != context["secret_arn"]
        or target["candidate_secret_arn"] != context["candidate_secret_arn"]
        or target["task_definition_arn"] != context["runtime"]["task_definition_arn"]
        or not isinstance(target["roles"], dict)
        or not 1 <= len(target["roles"]) <= 2
    ):
        raise ValueError("Exact runtime credential access target required")
    account = context["binding"]["account_id"]
    for arn, role_id in target["roles"].items():
        if (
            not isinstance(arn, str)
            or not re.fullmatch(rf"arn:aws:iam::{account}:role/[A-Za-z0-9+=,.@_/-]{{1,512}}", arn)
            or not isinstance(role_id, str)
            or not re.fullmatch(r"AROA[A-Z0-9]{17}", role_id)
            or arn == context["preparer_principal"]
        ):
            raise ValueError("Pinned runtime role identities distinct from preparer required")
    if len(set(target["roles"].values())) != len(target["roles"]):
        raise ValueError("Distinct runtime role identities required")
    return target


def validate_prior_role_ids(values):
    if (
        not isinstance(values, list)
        or len(values) > 20
        or any(not isinstance(v, str) or not re.fullmatch(r"AROA[A-Z0-9]{17}", v) for v in values)
        or values != sorted(set(values))
    ):
        raise ValueError("Bounded canonical historical runtime role identities required")
    return values


def deny_runtime_secret_policy(target, *, prior_role_ids=None):
    prior = validate_prior_role_ids([] if prior_role_ids is None else prior_role_ids)
    identities = sorted(value + ":*" for value in set(target["roles"].values()) | set(prior))
    if not identities:
        raise ValueError("At least one denied runtime identity required")
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyIncidentRuntimeCredentialAccess",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "secretsmanager:*",
                "Resource": target["secret_arn"],
                "Condition": {
                    "StringLike": {"aws:userid": identities[0] if len(identities) == 1 else identities}
                },
            }
        ],
    }


def runtime_secret_policy_matches(policy, target, *, prior_role_ids=None):
    """Normalize only IAM's scalar/list representation of this exact OR condition."""
    from copy import deepcopy

    try:
        normalized = deepcopy(policy)
        values = normalized["Statement"][0]["Condition"]["StringLike"]["aws:userid"]
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            return False
        expected = deny_runtime_secret_policy(target, prior_role_ids=prior_role_ids)
        identities = expected["Statement"][0]["Condition"]["StringLike"]["aws:userid"]
        if isinstance(identities, str):
            identities = [identities]
        if sorted(values) != identities:
            return False
        normalized["Statement"][0]["Condition"]["StringLike"]["aws:userid"] = (
            identities[0] if len(identities) == 1 else identities
        )
        return normalized == expected
    except (ValueError, TypeError, KeyError, IndexError):
        return False
