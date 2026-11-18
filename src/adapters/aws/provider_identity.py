"""Read-only AWS S3/SQS resource identity inspection."""

import hashlib
import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from adapters.runtime.provider_identity import (
    ObservedProviderResourceIdentity,
    RegisteredProviderResourceIdentity,
)
from domain.environment_transition import _ref


def _region(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d+", value):
        raise ValueError("Canonical AWS region required")


def aws_provider_identity_authority_ref(account_id, region, credential_source_ref, principal_role_ref):
    if not isinstance(account_id, str) or not re.fullmatch(r"\d{12}", account_id):
        raise ValueError("Canonical AWS account required")
    _region(region)
    _ref(credential_source_ref)
    _ref(principal_role_ref)
    digest = hashlib.sha256(
        json.dumps(
            {
                "account_id": account_id,
                "region": region,
                "credential_source_ref": credential_source_ref,
                "principal_role_ref": principal_role_ref,
                "profile": "aws-readonly-provider-identity-v1",
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return "aws-" + digest


def aws_resource_identity_sha256(*, resource_kind, account_id, region, identity):
    if resource_kind not in {"s3-bucket", "sqs-queue"}:
        raise ValueError("Bounded AWS provider resource kind required")
    if not isinstance(account_id, str) or not re.fullmatch(r"\d{12}", account_id):
        raise ValueError("Canonical AWS account required")
    _region(region)
    if not isinstance(identity, str) or not 1 <= len(identity.encode()) <= 1024:
        raise ValueError("Bounded AWS provider resource identity required")
    return hashlib.sha256(
        json.dumps(
            {
                "provider": "aws",
                "resource_kind": resource_kind,
                "account_id": account_id,
                "region": region,
                "identity": identity,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


@dataclass(frozen=True)
class RegisteredAwsProviderIdentityTarget:
    resource_ref: str
    resource_kind: str
    bucket_name: str = ""
    queue_url: str = ""

    def __post_init__(self):
        _ref(self.resource_ref)
        if self.resource_kind == "s3-bucket":
            if (
                not isinstance(self.bucket_name, str)
                or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", self.bucket_name)
                or ".." in self.bucket_name
                or self.queue_url
            ):
                raise ValueError("Canonical registered S3 bucket target required")
        elif self.resource_kind == "sqs-queue":
            if self.bucket_name or not isinstance(self.queue_url, str):
                raise ValueError("Canonical registered SQS queue target required")
        else:
            raise ValueError("Bounded AWS provider resource kind required")


class AwsProviderIdentityInspector:
    def __init__(
        self,
        *,
        account_id,
        region,
        authority_ref,
        credential_source_ref,
        principal_role_ref,
        targets,
        sts,
        s3,
        sqs,
        clock,
    ):
        if not isinstance(account_id, str) or not re.fullmatch(r"\d{12}", account_id):
            raise ValueError("Canonical AWS account required")
        _region(region)
        _ref(principal_role_ref)
        if authority_ref != aws_provider_identity_authority_ref(
            account_id, region, credential_source_ref, principal_role_ref
        ):
            raise ValueError("AWS provider authority registration changed")
        if (
            not isinstance(targets, tuple)
            or not 1 <= len(targets) <= 128
            or not all(isinstance(value, RegisteredAwsProviderIdentityTarget) for value in targets)
            or tuple(sorted(targets, key=lambda value: value.resource_ref)) != targets
            or len({value.resource_ref for value in targets}) != len(targets)
        ):
            raise ValueError("Canonical registered AWS provider targets required")
        if not all(
            callable(value)
            for value in (
                getattr(sts, "get_caller_identity", None),
                getattr(s3, "get_bucket_acl", None),
                getattr(s3, "get_bucket_location", None),
                getattr(sqs, "get_queue_attributes", None),
                clock,
            )
        ):
            raise TypeError("Read-only AWS provider clients and clock required")
        for target in targets:
            if target.resource_kind == "sqs-queue":
                parsed = urlsplit(target.queue_url)
                if (
                    parsed.scheme != "https"
                    or parsed.netloc != f"sqs.{region}.amazonaws.com"
                    or not re.fullmatch(rf"/{account_id}/[A-Za-z0-9_-]+(?:\.fifo)?", parsed.path)
                    or parsed.query
                    or parsed.fragment
                ):
                    raise ValueError("SQS target must belong to the registered account and region")
        self.account_id = account_id
        self.region = region
        self.principal_role_ref = principal_role_ref
        self.authority_ref = authority_ref
        self.targets = {value.resource_ref: value for value in targets}
        self.sts, self.s3, self.sqs, self.clock = sts, s3, sqs, clock

    def inspect(self, resource):
        if not isinstance(resource, RegisteredProviderResourceIdentity):
            raise TypeError("Registered provider resource identity required")
        if resource.provider_ref != "aws":
            raise ValueError("AWS inspector requires an AWS resource")
        target = self.targets.get(resource.resource_ref)
        if target is None or target.resource_kind != resource.resource_kind:
            raise ValueError("Registered AWS provider target changed")
        try:
            caller = self.sts.get_caller_identity()
            arn = caller.get("Arn") if isinstance(caller, dict) else None
            if (
                not isinstance(caller, dict)
                or caller.get("Account") != self.account_id
                or not isinstance(arn, str)
                or not re.fullmatch(
                    rf"arn:aws:sts::{self.account_id}:assumed-role/"
                    rf"{re.escape(self.principal_role_ref)}/[A-Za-z0-9+=,.@_-]{{1,64}}",
                    arn,
                )
            ):
                raise ValueError("AWS provider authority changed")
            if target.resource_kind == "s3-bucket":
                acl = self.s3.get_bucket_acl(
                    Bucket=target.bucket_name,
                    ExpectedBucketOwner=self.account_id,
                )
                location = self.s3.get_bucket_location(
                    Bucket=target.bucket_name,
                    ExpectedBucketOwner=self.account_id,
                )
                owner = acl.get("Owner", {}).get("ID") if isinstance(acl, dict) else None
                observed_region = location.get("LocationConstraint") if isinstance(location, dict) else None
                observed_region = observed_region or "us-east-1"
                if (
                    not isinstance(owner, str)
                    or not re.fullmatch(r"[a-f0-9]{64}", owner)
                    or observed_region != self.region
                ):
                    raise ValueError("S3 provider identity changed")
                identity = target.bucket_name + ":" + owner
            else:
                response = self.sqs.get_queue_attributes(
                    QueueUrl=target.queue_url,
                    AttributeNames=["QueueArn"],
                )
                arn = response.get("Attributes", {}).get("QueueArn") if isinstance(response, dict) else None
                parsed = urlsplit(target.queue_url)
                name = parsed.path.rsplit("/", 1)[-1]
                expected_arn = f"arn:aws:sqs:{self.region}:{self.account_id}:{name}"
                if arn != expected_arn:
                    raise ValueError("SQS provider identity changed")
                identity = arn
            digest = aws_resource_identity_sha256(
                resource_kind=target.resource_kind,
                account_id=self.account_id,
                region=self.region,
                identity=identity,
            )
            observed_at = self.clock()
            return ObservedProviderResourceIdentity(
                resource.logical_ref,
                "aws",
                target.resource_kind,
                target.resource_ref,
                digest,
                self.authority_ref,
                observed_at,
            )
        except Exception:  # noqa: BLE001 -- AWS diagnostics and identifiers remain private
            raise OSError("Registered AWS provider identity unavailable") from None
