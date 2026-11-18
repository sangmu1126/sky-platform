"""Opt-in live AWS provider identity smoke with fully disposable resources."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import uuid
from datetime import UTC, datetime

import boto3
from botocore.exceptions import ClientError

from adapters.aws.provider_identity import (
    AwsProviderIdentityInspector,
    RegisteredAwsProviderIdentityTarget,
    aws_provider_identity_authority_ref,
    aws_resource_identity_sha256,
)
from adapters.runtime.provider_identity import RegisteredProviderResourceIdentity


def _client_error_code(error: ClientError) -> str:
    return str(error.response.get("Error", {}).get("Code", ""))


def _wait_absent(check, missing_codes: set[str], description: str) -> None:
    deadline = time.monotonic() + 60
    while True:
        try:
            check()
        except ClientError as error:
            if _client_error_code(error) in missing_codes:
                return
            raise
        if time.monotonic() >= deadline:
            raise RuntimeError(f"Timed out confirming {description} retirement")
        time.sleep(2)


def _retry_client_error(call, retry_codes: set[str], description: str):
    deadline = time.monotonic() + 90
    while True:
        try:
            return call()
        except ClientError as error:
            if _client_error_code(error) not in retry_codes or time.monotonic() >= deadline:
                raise RuntimeError(f"Timed out waiting for {description}") from None
            time.sleep(2)


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(
        description="Create, inspect, and retire temporary S3/SQS provider identity resources"
    )
    parser.add_argument("--apply", action="store_true", help="Create temporary billable AWS resources")
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile", default="default")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"\d{12}", args.account):
        parser.error("--account must be a 12-digit AWS account ID")
    if not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d+", args.region):
        parser.error("--region must be a canonical AWS region")

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    sts = session.client("sts")
    caller = sts.get_caller_identity()
    caller_arn = caller.get("Arn", "")
    if caller.get("Account") != args.account or not re.fullmatch(
        rf"arn:aws:iam::{args.account}:(?:user|role)/[A-Za-z0-9+=,.@_/-]+", caller_arn
    ):
        raise SystemExit("AWS account or caller identity differs; no resources were created")

    suffix = uuid.uuid4().hex[:12]
    bucket_name = f"sky-provider-check-{args.account}-{suffix}"
    queue_name = f"sky-provider-check-{suffix}"
    role_name = f"sky-provider-check-{suffix}"
    policy_name = "sky-provider-readonly"
    queue_arn = f"arn:aws:sqs:{args.region}:{args.account}:{queue_name}"
    queue_url = f"https://sqs.{args.region}.amazonaws.com/{args.account}/{queue_name}"
    bucket_arn = f"arn:aws:s3:::{bucket_name}"
    plan = {
        "account": args.account,
        "region": args.region,
        "resources": ["temporary S3 bucket", "temporary SQS queue", "temporary read-only IAM role"],
        "retirement": "required and verified",
    }
    print(json.dumps(plan, ensure_ascii=False, sort_keys=True), flush=True)
    if not args.apply:
        print("Read-only preflight complete; --apply is required to create resources", flush=True)
        return

    s3 = session.client("s3")
    sqs = session.client("sqs")
    iam = session.client("iam")
    bucket_created = queue_created = role_created = policy_created = False
    try:
        bucket_args = {"Bucket": bucket_name}
        if args.region != "us-east-1":
            bucket_args["CreateBucketConfiguration"] = {"LocationConstraint": args.region}
        s3.create_bucket(**bucket_args)
        bucket_created = True
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        s3.put_bucket_tagging(
            Bucket=bucket_name,
            Tagging={
                "TagSet": [
                    {"Key": "sky-managed", "Value": "true"},
                    {"Key": "sky-purpose", "Value": "provider-check"},
                ]
            },
        )
        created_queue = sqs.create_queue(
            QueueName=queue_name,
            tags={"sky-managed": "true", "sky-purpose": "provider-check"},
        )
        queue_created = True
        if created_queue.get("QueueUrl") != queue_url:
            raise RuntimeError("Temporary SQS queue identity differs")

        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": caller_arn},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        created_role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust, separators=(",", ":")),
            Description="Disposable Sky provider identity inspection role",
            MaxSessionDuration=3600,
            Tags=[
                {"Key": "sky-managed", "Value": "true"},
                {"Key": "sky-purpose", "Value": "provider-check"},
            ],
        )
        role_created = True
        role_arn = f"arn:aws:iam::{args.account}:role/{role_name}"
        if created_role.get("Role", {}).get("Arn") != role_arn:
            raise RuntimeError("Temporary IAM role identity differs")
        permissions = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetBucketAcl", "s3:GetBucketLocation"],
                    "Resource": bucket_arn,
                },
                {
                    "Effect": "Allow",
                    "Action": "sqs:GetQueueAttributes",
                    "Resource": queue_arn,
                },
            ],
        }
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(permissions, separators=(",", ":")),
        )
        policy_created = True

        assumed = _retry_client_error(
            lambda: sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="sky-provider-check",
                DurationSeconds=900,
            ),
            {"AccessDenied", "AccessDeniedException", "NoSuchEntity"},
            "temporary IAM role propagation",
        )["Credentials"]
        inspection_session = boto3.Session(
            aws_access_key_id=assumed["AccessKeyId"],
            aws_secret_access_key=assumed["SecretAccessKey"],
            aws_session_token=assumed["SessionToken"],
            region_name=args.region,
        )
        inspection_sts = inspection_session.client("sts")
        inspection_s3 = inspection_session.client("s3")
        inspection_sqs = inspection_session.client("sqs")
        owner_id = _retry_client_error(
            lambda: inspection_s3.get_bucket_acl(Bucket=bucket_name, ExpectedBucketOwner=args.account),
            {"AccessDenied", "AccessDeniedException"},
            "read-only role policy propagation",
        )["Owner"]["ID"]
        if not re.fullmatch(r"[a-f0-9]{64}", owner_id):
            raise RuntimeError("Canonical S3 owner identity unavailable")

        authority_ref = aws_provider_identity_authority_ref(
            args.account, args.region, "default-admin-profile", role_name
        )
        bucket_resource = RegisteredProviderResourceIdentity(
            "live-object-store",
            "object_store",
            "aws-live-source",
            "aws",
            "s3-bucket",
            "live-bucket-target",
            aws_resource_identity_sha256(
                resource_kind="s3-bucket",
                account_id=args.account,
                region=args.region,
                identity=f"{bucket_name}:{owner_id}",
            ),
            authority_ref,
        )
        queue_resource = RegisteredProviderResourceIdentity(
            "live-queue",
            "queue",
            "aws-live-source",
            "aws",
            "sqs-queue",
            "live-queue-target",
            aws_resource_identity_sha256(
                resource_kind="sqs-queue",
                account_id=args.account,
                region=args.region,
                identity=queue_arn,
            ),
            authority_ref,
        )
        inspector = AwsProviderIdentityInspector(
            account_id=args.account,
            region=args.region,
            authority_ref=authority_ref,
            credential_source_ref="default-admin-profile",
            principal_role_ref=role_name,
            targets=(
                RegisteredAwsProviderIdentityTarget(
                    "live-bucket-target", "s3-bucket", bucket_name=bucket_name
                ),
                RegisteredAwsProviderIdentityTarget("live-queue-target", "sqs-queue", queue_url=queue_url),
            ),
            sts=inspection_sts,
            s3=inspection_s3,
            sqs=inspection_sqs,
            clock=lambda: datetime.now(UTC),
        )
        observed = (inspector.inspect(bucket_resource), inspector.inspect(queue_resource))
        if tuple(value.identity_sha256 for value in observed) != (
            bucket_resource.identity_sha256,
            queue_resource.identity_sha256,
        ):
            raise RuntimeError("Live provider identity evidence differs from registration")
        print(
            json.dumps(
                {
                    "status": "verified",
                    "resource_kinds": [value.resource_kind for value in observed],
                    "authority_ref": authority_ref,
                    "observed_at": [value.observed_at.isoformat() for value in observed],
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            flush=True,
        )
    finally:
        original_error = sys.exc_info()[1]
        cleanup_errors = []
        if queue_created:
            try:
                sqs.delete_queue(QueueUrl=queue_url)
                _wait_absent(
                    lambda: sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"]),
                    {"AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"},
                    "SQS queue",
                )
            except Exception as error:  # noqa: BLE001 -- retain every cleanup error
                cleanup_errors.append(f"SQS:{type(error).__name__}")
        if bucket_created:
            try:
                s3.delete_bucket(Bucket=bucket_name, ExpectedBucketOwner=args.account)
                _wait_absent(
                    lambda: s3.head_bucket(Bucket=bucket_name, ExpectedBucketOwner=args.account),
                    {"404", "NoSuchBucket", "NotFound"},
                    "S3 bucket",
                )
            except Exception as error:  # noqa: BLE001 -- retain every cleanup error
                cleanup_errors.append(f"S3:{type(error).__name__}")
        if policy_created:
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
            except Exception as error:  # noqa: BLE001 -- retain every cleanup error
                cleanup_errors.append(f"IAM-policy:{type(error).__name__}")
        if role_created:
            try:
                iam.delete_role(RoleName=role_name)
                _wait_absent(
                    lambda: iam.get_role(RoleName=role_name),
                    {"NoSuchEntity"},
                    "IAM role",
                )
            except Exception as error:  # noqa: BLE001 -- retain every cleanup error
                cleanup_errors.append(f"IAM-role:{type(error).__name__}")
        if cleanup_errors:
            message = "Temporary provider resource cleanup needs attention: " + ", ".join(cleanup_errors)
            if original_error is not None:
                original_error.add_note(message)
            else:
                raise RuntimeError(message)
        if bucket_created or queue_created or role_created:
            print("PASS: temporary S3, SQS, and IAM resources retired and absence confirmed", flush=True)


if __name__ == "__main__":
    main()
