"""Short execution delegation in a worker-write/builder-read S3 prefix.

A grant cannot make in-flight AWS requests atomic with DB revocation. Its maximum
validity is 45 seconds, with bounded S3 date precision. Unavailable/expired grants
stop new effects; they never refund quotas or authorize workload deployment.
"""

import json
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime

from botocore.config import Config
from botocore.exceptions import ClientError

from ports.remote_builds import canonical, digest, identity

FIELDS = {
    "version",
    "request_digest",
    "build_id",
    "attempt_id",
    "lease_epoch",
    "lease_owner",
    "state",
    "issued_at",
    "expires_at",
    "budget",
}


class S3BuildExecutionGrants:
    def __init__(self, settings, *, client=None, clock=lambda: datetime.now(UTC), authorization=None):
        self.settings, self.clock, self.authorization = settings, clock, authorization
        if client is None:
            import boto3

            client = boto3.client(
                "s3",
                region_name=settings.region,
                config=Config(connect_timeout=3, read_timeout=8, retries={"total_max_attempts": 1}),
            )
        self.client = client
        self.pinned = None

    def _scope(self, request):
        if (request["account_id"], request["region"], request["bucket"]) != (
            self.settings.account_id,
            self.settings.region,
            self.settings.bucket,
        ):
            raise ValueError("Execution grant account/region/bucket differs from registered source")
        return "execution-grants/" + identity(request["build_id"]) + ".json"

    def _read(self, request, *, missing=False):
        key = self._scope(request)
        try:
            response = self.client.get_object(
                Bucket=self.settings.bucket, Key=key, ExpectedBucketOwner=self.settings.account_id
            )
        except ClientError as error:
            if missing and error.response.get("Error", {}).get("Code") in {"NoSuchKey", "404"}:
                return None, None, None
            raise OSError("Execution delegation unavailable; stop new effects") from None
        body = response["Body"]
        try:
            raw = body.read(4097)
        finally:
            body.close()
        if len(raw) > 4096:
            raise ValueError("Execution grant exceeds bound")
        value = json.loads(raw)
        if (
            not isinstance(value, dict)
            or set(value) != FIELDS
            or raw != canonical(value)
            or type(value["version"]) is not int
            or value["version"] != 1
            or value["request_digest"] != digest(request)
            or value["build_id"] != request["build_id"]
            or not isinstance(value["lease_owner"], str)
            or not 1 <= len(value["lease_owner"]) <= 128
            or type(value["lease_epoch"]) is not int
            or not 1 <= value["lease_epoch"] < 2**63
            or value["state"] not in {"active", "revoked"}
        ):
            raise ValueError("Execution grant identity or binding differs")
        identity(value["attempt_id"])
        issued, expires = (datetime.fromisoformat(value[k]) for k in ("issued_at", "expires_at"))
        if any(t.tzinfo is None for t in (issued, expires)) or not issued < expires <= issued + timedelta(
            seconds=45
        ):
            raise ValueError("Execution delegation exceeds its maximum lifetime")
        etag = response.get("ETag")
        if not isinstance(etag, str) or not 1 <= len(etag) <= 256:
            raise ValueError("Conditional execution grant identity required")
        return value, etag, response

    def renew(self, request, lease, *, guard):
        guard()
        authorized = self.authorization(request, lease) if self.authorization is not None else None
        if self.authorization is not None and authorized is None:
            return None
        now = self.clock()
        value = {
            "version": 1,
            "request_digest": digest(request),
            "build_id": request["build_id"],
            "attempt_id": lease.attempt_id,
            "lease_epoch": lease.epoch,
            "lease_owner": lease.owner,
            "state": "active",
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=45)).isoformat(),
            "budget": None,
        }
        if authorized is not None:
            value.update(authorized)
        guard()
        # A narrow GetObject role receives 403, not 404, for absent keys when
        # it cannot ListBucket. Conditional creation avoids treating 403 as
        # absence or broadening the role to enumerate other applications.
        if self._put(request, value, None, create_only=True):
            try:
                guard()
            except Exception:
                self.revoke(request, lease)
                raise
            return value
        guard()
        existing, etag, _ = self._read(request)
        if existing and (
            existing["lease_epoch"] > lease.epoch
            or (
                existing["lease_epoch"] == lease.epoch
                and (existing["lease_owner"] != lease.owner or existing["state"] == "revoked")
            )
        ):
            raise ValueError("A newer or revoked execution delegation cannot be overwritten")
        guard()
        self._put(request, value, etag)
        try:
            guard()
        except Exception:
            self.revoke(request, lease)
            raise
        return value

    def _put(self, request, value, etag, *, create_only=False):
        condition = {"IfNoneMatch": "*"} if etag is None else {"IfMatch": etag}
        try:
            self.client.put_object(
                Bucket=self.settings.bucket,
                Key=self._scope(request),
                ExpectedBucketOwner=self.settings.account_id,
                Body=canonical(value),
                ContentType="application/json",
                ServerSideEncryption="AES256",
                **condition,
            )
        except ClientError as error:
            if create_only and error.response.get("Error", {}).get("Code") in {"PreconditionFailed", "412"}:
                return False
            raise OSError("Execution delegation write uncertain or fenced; do not replay effects") from None
        return True

    def revoke(self, request, lease):
        value, etag, _ = self._read(request, missing=True)
        if value is None:
            return
        if (value["lease_epoch"], value["lease_owner"], value["attempt_id"]) != (
            lease.epoch,
            lease.owner,
            lease.attempt_id,
        ):
            return  # A stale worker cannot revoke a different owner's delegation.
        if value["state"] == "revoked":
            return
        self._put(request, {**value, "state": "revoked"}, etag)

    def require(self, request, *, require_budget=False):
        value, _, response = self._read(request)
        header = response.get("ResponseMetadata", {}).get("HTTPHeaders", {}).get("date")
        if not isinstance(header, str):
            raise ValueError("Authenticated S3 response date required")
        server = parsedate_to_datetime(header)
        local = self.clock()
        issued = datetime.fromisoformat(value["issued_at"])
        expires = datetime.fromisoformat(value["expires_at"])
        if (
            server.tzinfo is None
            or local.tzinfo is None
            or abs((server - local).total_seconds()) > 5
            or value["state"] != "active"
            or not issued <= server + timedelta(seconds=1)
            or server >= expires
        ):
            raise ValueError("Build execution delegation expired, revoked or clock is untrusted")
        pin = (value["attempt_id"], value["lease_epoch"], value["lease_owner"])
        if self.pinned is not None and pin != self.pinned:
            raise ValueError("Build execution owner changed; old runner cannot borrow a new lease")
        self.pinned = pin
        budget = value["budget"]
        if require_budget and (
            not isinstance(budget, dict)
            or set(budget) != {"key", "policy_digest", "caps"}
            or not isinstance(budget["caps"], dict)
            or not budget["caps"]
            or any(type(v) is not int or v < 0 for v in budget["caps"].values())
            or not isinstance(budget["key"], str)
            or not budget["key"].startswith(request["build_id"] + ":")
            or not isinstance(budget["policy_digest"], str)
            or len(budget["policy_digest"]) != 64
        ):
            raise ValueError("Hosted execution requires the committed operation budget")
        return {
            "request_digest": value["request_digest"],
            "lease_epoch": value["lease_epoch"],
            "expires_at": value["expires_at"],
            "current_execution_delegation": True,
            "database_revocation_atomic_with_aws": False,
            "budget_verified": require_budget,
            "budget_caps": budget["caps"] if require_budget else {},
        }


def execution_guard(request, settings, scope_guard, *, environment=None):
    """Lazy credential lookup after callers have validated untrusted artifacts."""
    import os

    env = os.environ if environment is None else environment
    hosted = env.get("GITHUB_ACTIONS") == "true"
    required = env.get("SKY_REQUIRE_EXECUTION_GRANTS", "true" if hosted else "false")
    if required not in {"true", "false"} or (hosted and required != "true"):
        raise ValueError("Hosted builders require current worker-owned execution delegations")
    reader = None

    def guard():
        nonlocal reader
        scope_guard()
        if required == "true":
            if reader is None:
                reader = S3BuildExecutionGrants(settings)
            return reader.require(request, require_budget=True)

    return guard
