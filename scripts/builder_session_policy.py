"""Bound OIDC sessions to one admitted pointer before they can access S3/ECR."""

import argparse
import json
import os
import re
from uuid import UUID


def policy(mode, env):
    job = env["BUILD_ID"]
    key = env["REQUEST_KEY"]
    account = env["SKY_AWS_ACCOUNT_ID"]
    region = env["AWS_REGION"]
    bucket = env["SKY_ARTIFACTS_BUCKET"]
    if (
        str(UUID(job)) != job
        or not re.fullmatch("[a-f0-9]{64}", env["REQUEST_DIGEST"])
        or not re.fullmatch("[0-9]{12}", account)
        or not re.fullmatch("[a-z]{2}(?:-[a-z]+)+-\\d+", region)
        or not re.fullmatch("[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", bucket)
        or not re.fullmatch(
            r"sources/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[0-9a-f]{32}/build-requests/"
            + re.escape(job)
            + r"\.json",
            key,
        )
    ):
        raise ValueError("Exact admitted job/request and operator AWS registration required")
    prefix = key.rsplit("/build-requests/", 1)[0]
    grant = f"arn:aws:s3:::{bucket}/execution-grants/{job}.json"
    statements = [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": [grant]}]
    if mode == "prepare":
        statements[0]["Resource"] += [f"arn:aws:s3:::{bucket}/{key}", f"arn:aws:s3:::{bucket}/{prefix}/*"]
    elif mode == "controller":
        role = env["SKY_BUILD_CONTROLLER_ROLE_ARN"]
        materials = env["SKY_TRUSTED_BUILD_MATERIALS_PREFIX"]
        if not re.fullmatch(
            f"arn:aws:iam::{account}:role/sky-[a-z0-9-]+-controller", role
        ) or not re.fullmatch("trusted-build-materials/[a-f0-9]{64}", materials):
            raise ValueError("Registered immutable controller/materials scope required")
        statements += [
            {"Effect": "Allow", "Action": ["sts:AssumeRole", "sts:TagSession"], "Resource": [role]},
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{bucket}/{materials}/*"],
            },
        ]
    elif mode == "publish":
        signing = env["SKY_BUILD_SIGNING_KEY_ARN"]
        if not re.fullmatch(f"arn:aws:kms:{region}:{account}:key/[a-f0-9-]{{36}}", signing):
            raise ValueError("Exact registered signing key required")
        statements += [
            {
                "Effect": "Allow",
                "Action": [
                    "ecr:DescribeRepositories",
                    "ecr:ListTagsForResource",
                    "ecr:DescribeImages",
                    "ecr:BatchGetImage",
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:InitiateLayerUpload",
                    "ecr:UploadLayerPart",
                    "ecr:CompleteLayerUpload",
                    "ecr:PutImage",
                ],
                "Resource": [f"arn:aws:ecr:{region}:{account}:repository/sky-managed"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject"],
                "Resource": [f"arn:aws:s3:::{bucket}/builds/{job}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["kms:DescribeKey", "kms:GetPublicKey", "kms:Sign"],
                "Resource": [signing],
            },
            {"Effect": "Deny", "Action": ["ecr:GetAuthorizationToken"], "Resource": ["*"]},
        ]
    else:
        raise ValueError("Registered workflow phase required")
    return {"Version": "2012-10-17", "Statement": statements}


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("phase", choices=("prepare", "controller", "publish"))
    args = parser.parse_args()
    value = json.dumps(policy(args.phase, os.environ), sort_keys=True, separators=(",", ":"))
    if len(value) > 2048:
        raise ValueError("Session policy exceeds STS inline limit")
    with open(os.environ["GITHUB_OUTPUT"], "a") as out:
        out.write("policy=" + value + "\n")


if __name__ == "__main__":
    main()
