"""Small canonical audit facts under independently scoped append-only S3 authority."""

import hashlib
import json
import re
from datetime import datetime, timedelta
from uuid import UUID

from botocore.config import Config
from botocore.exceptions import ClientError

from application.security_observations import RULES

FIELDS = {
    "version",
    "kind",
    "severity",
    "event_id",
    "organization_id",
    "application_id",
    "job_id",
    "source_digest",
    "record_revision",
    "detector_id",
    "observed_at",
    "detected_at",
    "evidence_digest",
    "security_clearance",
}


def audit_bytes(event, organization_id, application_id):
    if any(
        not isinstance(v, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", v)
        for v in (organization_id, application_id)
    ):
        raise ValueError("Exact audit scope required")
    if (
        not isinstance(event, dict)
        or set(event) != FIELDS
        or type(event["version"]) is not int
        or event["version"] != 1
        or event["organization_id"] != organization_id
        or event["application_id"] != application_id
        or event["kind"] not in RULES
        or event["severity"] != RULES[event["kind"]][0]
        or event["security_clearance"] is not False
    ):
        raise ValueError("Only exact app-scoped typed security facts may enter audit storage")
    if (
        not isinstance(event["event_id"], str)
        or str(UUID(event["event_id"])) != event["event_id"]
        or any(
            not isinstance(event[k], str) or not re.fullmatch(pattern, event[k])
            for k, pattern in (
                ("job_id", r"[0-9a-f]{16}"),
                ("source_digest", r"[0-9a-f]{64}"),
                ("evidence_digest", r"[0-9a-f]{64}"),
                ("detector_id", r"[A-Za-z0-9_-]{1,64}"),
            )
        )
        or type(event["record_revision"]) is not int
        or not 1 <= event["record_revision"] < 2**63
    ):
        raise ValueError("Audit identifiers must be bounded canonical identities, never free text")
    observed, detected = (datetime.fromisoformat(event[k]) for k in ("observed_at", "detected_at"))
    if (
        observed.tzinfo is None
        or detected.tzinfo is None
        or not observed <= detected <= observed + timedelta(minutes=15)
    ):
        raise ValueError("Bounded timezone-aware audit observation required")
    # No arbitrary message/source/Secret field is accepted by this boundary.
    raw = json.dumps(event, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(raw) > 4096:
        raise ValueError("Audit fact exceeds bound")
    return raw


class S3SecurityAudit:
    def __init__(self, *, bucket, account_id, region, organization_id, application_id, session):
        if (
            not isinstance(bucket, str)
            or not re.fullmatch(r"sky-security-[a-z0-9-]{1,48}", bucket)
            or not re.fullmatch(r"[0-9]{12}", account_id)
            or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d+", region)
            or any(
                not isinstance(v, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", v)
                for v in (organization_id, application_id)
            )
        ):
            raise ValueError("Pinned audit account/bucket/app scope required")
        self.bucket, self.account_id, self.org, self.app = bucket, account_id, organization_id, application_id
        self.client = session.client(
            "s3",
            region_name=region,
            config=Config(connect_timeout=5, read_timeout=15, retries={"total_max_attempts": 1}),
        )

    def append(self, event):
        raw = audit_bytes(event, self.org, self.app)
        identity = hashlib.sha256(raw).hexdigest()
        key = f"audit/{self.org}/{self.app}/{identity}.json"
        try:
            response = self.client.put_object(
                Bucket=self.bucket,
                ExpectedBucketOwner=self.account_id,
                Key=key,
                Body=raw,
                ContentType="application/json",
                IfNoneMatch="*",
                ServerSideEncryption="AES256",
            )
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") not in {"PreconditionFailed", "412"}:
                raise
            return {"sha256": identity, "append_confirmed": False, "already_exists": True}
        if not response.get("VersionId"):
            raise ValueError("Audit bucket must preserve object versions")
        return {
            "sha256": identity,
            "version_id": response["VersionId"],
            "append_confirmed": True,
            "security_clearance": False,
        }
