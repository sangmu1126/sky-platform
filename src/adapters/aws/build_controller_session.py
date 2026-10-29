"""Controller-only, temporary job-tagged role; no credential enters the guest."""

import os
import re
from uuid import UUID


def controller_session(profile, session, job, *, environment=None):
    env = os.environ if environment is None else environment
    role = env.get("SKY_BUILD_CONTROLLER_ROLE_ARN")
    hosted = env.get("GITHUB_ACTIONS") == "true" or bool(
        env.get("ECS_CONTAINER_METADATA_URI_V4") or env.get("ECS_CONTAINER_METADATA_URI")
    )
    if role is None and not hosted:
        return session  # Explicit trusted local developer composition only.
    if (
        not isinstance(role, str)
        or not re.fullmatch(f"arn:aws:iam::{profile.account_id}:role/sky-[a-z0-9-]+-controller", role)
        or not isinstance(job, str)
        or str(UUID(job)) != job
    ):
        raise ValueError("Hosted VM control requires the registered job-scoped controller role")
    sts = session.client("sts", region_name=profile.region)
    if sts.get_caller_identity().get("Account") != profile.account_id:
        raise ValueError("Controller source account differs")
    credentials = sts.assume_role(
        RoleArn=role,
        RoleSessionName="sky-vm-" + job[:12],
        DurationSeconds=900,
        Tags=[{"Key": "sky:JobId", "Value": job}],
    )["Credentials"]
    import boto3

    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=profile.region,
    )
