"""Deterministic identity for an isolated incident credential candidate."""

import re


def candidate_secret_name(resource_id, operation_id):
    if not isinstance(resource_id, str) or not re.fullmatch(r"db-[A-Za-z0-9]{1,64}", resource_id):
        raise ValueError("Pinned RDS resource identity required")
    if not isinstance(operation_id, str) or not re.fullmatch(r"[a-f0-9]{32}", operation_id):
        raise ValueError("Exact credential preparation identity required")
    return f"sky-incident/{resource_id}/{operation_id}"


def candidate_resource_policy(arn, principal_arn):
    """Callers pin candidate ownership and the preparer before using this policy."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyUnapprovedIncidentCredentialAccess",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "secretsmanager:*",
                "Resource": arn,
                "Condition": {"ArnNotEquals": {"aws:PrincipalArn": principal_arn}},
            }
        ],
    }
