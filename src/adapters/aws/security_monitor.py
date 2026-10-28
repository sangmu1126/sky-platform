"""Read-only CloudTrail observation for exact registered forbidden Secret reads.

Does not accept application logs, execute a hold, fetch Secret values, or infer
that absence of matching events means no compromise. CloudTrail has delivery lag.
The operator must register full forbidden ARNs; normal app Secret access is not
an incident. This collector does not cover data/network/console attack classes.
"""

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID


@dataclass(frozen=True)
class SecretAccessRegistration:
    account_id: str
    region: str
    role_arn: str
    role_id: str
    forbidden_secrets: tuple[str, ...]

    def __post_init__(self):
        if (
            not re.fullmatch(r"[0-9]{12}", self.account_id)
            or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d+", self.region)
            or not re.fullmatch(
                r"arn:aws:iam::" + self.account_id + r":role/[A-Za-z0-9+=,.@_/-]+", self.role_arn
            )
            or not re.fullmatch(r"AROA[A-Z0-9]{17}", self.role_id)
            or not isinstance(self.forbidden_secrets, tuple)
            or not 1 <= len(self.forbidden_secrets) <= 16
            or any(
                not isinstance(arn, str)
                or not re.fullmatch(
                    r"arn:aws:secretsmanager:"
                    + self.region
                    + ":"
                    + self.account_id
                    + r":secret:[A-Za-z0-9!/_+=.@-]+-[A-Za-z0-9]{6}",
                    arn,
                )
                for arn in self.forbidden_secrets
            )
        ):
            raise ValueError("Exact role identity and forbidden Secret registration required")


class CloudTrailSecretAccessMonitor:
    def __init__(self, registration, *, session=None):
        if not isinstance(registration, SecretAccessRegistration):
            raise ValueError("Trusted security monitor registration required")
        if session is None:
            import boto3

            session = boto3.Session(region_name=registration.region)
        from botocore.config import Config

        config = Config(connect_timeout=5, read_timeout=15, retries={"total_max_attempts": 1})
        self.sts = session.client("sts", region_name=registration.region, config=config)
        self.trail = session.client("cloudtrail", region_name=registration.region, config=config)
        self.registration = registration

    def observe(self, *, now):
        stamp = datetime.fromisoformat(now)
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise ValueError("Timezone-aware collector time required")
        r = self.registration
        if self.sts.get_caller_identity().get("Account") != r.account_id:
            raise ValueError("Security monitor account mismatch")
        start = stamp - timedelta(minutes=15)
        matches, seen, denied, count = [], set(), 0, 0
        token = None
        for _ in range(3):
            args = {
                "LookupAttributes": [
                    {"AttributeKey": "EventSource", "AttributeValue": "secretsmanager.amazonaws.com"}
                ],
                "StartTime": start,
                "EndTime": stamp,
                "MaxResults": 50,
            }
            if token:
                args["NextToken"] = token
            result = self.trail.lookup_events(**args)
            if not isinstance(result.get("Events"), list) or len(result["Events"]) > 50:
                raise ValueError("Invalid CloudTrail response")
            for event in result["Events"]:
                count += 1
                if not isinstance(event, dict):
                    raise ValueError("Invalid CloudTrail event record")
                raw = event.get("CloudTrailEvent")
                if not isinstance(raw, str) or len(raw.encode()) > 262144:
                    raise ValueError("Invalid bounded CloudTrail event")
                document = json.loads(raw)
                if not isinstance(document, dict):
                    raise ValueError("Invalid CloudTrail event object")
                identity = document.get("userIdentity") or {}
                if not isinstance(identity, dict):
                    raise ValueError("Invalid CloudTrail identity")
                context = identity.get("sessionContext") or {}
                parameters = document.get("requestParameters") or {}
                if not isinstance(context, dict) or not isinstance(parameters, dict):
                    raise ValueError("Invalid CloudTrail event scope")
                issuer = context.get("sessionIssuer") or {}
                if not isinstance(issuer, dict):
                    raise ValueError("Invalid CloudTrail session issuer")
                if (
                    document.get("eventSource") != "secretsmanager.amazonaws.com"
                    or document.get("eventName") != "GetSecretValue"
                    or document.get("recipientAccountId") != r.account_id
                    or document.get("awsRegion") != r.region
                    or identity.get("type") != "AssumedRole"
                    or issuer.get("arn") != r.role_arn
                    or not str(identity.get("principalId", "")).startswith(r.role_id + ":")
                    or parameters.get("secretId") not in r.forbidden_secrets
                ):
                    continue
                event_id = document.get("eventID")
                if not isinstance(event_id, str) or str(UUID(event_id)) != event_id:
                    raise ValueError("Invalid CloudTrail event identity")
                observed = datetime.fromisoformat(document["eventTime"].replace("Z", "+00:00"))
                if observed.tzinfo is None or not start <= observed <= stamp:
                    raise ValueError("CloudTrail event time outside collection window")
                if event_id in seen:
                    continue
                seen.add(event_id)
                if document.get("errorCode"):
                    denied += 1
                else:
                    matches.append(event_id)
            token = result.get("NextToken")
            if not token:
                break
            if not isinstance(token, str) or not 1 <= len(token) <= 4096:
                raise ValueError("Invalid CloudTrail continuation")
        return {
            "version": 1,
            "observed_at": stamp.isoformat(),
            "window_seconds": 900,
            "events_examined": count,
            "matching_successful_forbidden_reads": sorted(matches),
            "matching_denied_reads": denied,
            "collection_complete": not bool(token),
            "requires_operator_review": bool(matches),
            "automatic_hold_executed": False,
            "absence_of_compromise_proven": False,
        }
