"""Machine review notification to a dedicated account-bound queue, never Slack/email."""

import json
import re


class SecurityReviewQueue:
    def __init__(self, url, *, account_id, region, session):
        if not re.fullmatch(
            r"https://sqs\."
            + re.escape(region)
            + r"\.amazonaws\.com/"
            + re.escape(account_id)
            + r"/sky-[a-z0-9-]+-review",
            url,
        ):
            raise ValueError("Dedicated same-account security review queue required")
        self.url, self.account, self.region = url, account_id, region
        self.client = session.client("sqs", region_name=region)

    def notify(self, result):
        event = result["event"]
        if (
            not result.get("audit", {}).get("append_confirmed")
            or result.get("automatic_release_permitted") is not False
        ):
            raise ValueError("Confirmed independent audit required before review notification")
        import hashlib

        from adapters.aws.security_audit import audit_bytes

        raw = audit_bytes(event, event.get("organization_id"), event.get("application_id"))
        if result["audit"].get("sha256") != hashlib.sha256(raw).hexdigest():
            raise ValueError("Notification differs from the independently stored audit fact")
        proposal = result.get("signed_hold_proposal")
        if proposal is not None:
            import base64
            from datetime import datetime, timedelta
            from application.security_observations import RULES

            payload = proposal.get("payload") if isinstance(proposal, dict) else None
            fields = {
                "version",
                "detector_id",
                "event_id",
                "organization_id",
                "application_id",
                "job_id",
                "source_digest",
                "record_revision",
                "reason",
                "observed_at",
                "expires_at",
            }
            if (
                not isinstance(proposal, dict)
                or set(proposal) != {"payload", "signature"}
                or not isinstance(payload, dict)
                or set(payload) != fields
                or type(payload.get("version")) is not int
                or payload["version"] != 1
                or any(
                    payload.get(name) != event[name]
                    for name in (
                        "detector_id",
                        "organization_id",
                        "application_id",
                        "job_id",
                        "source_digest",
                        "record_revision",
                    )
                )
                or payload["event_id"] != hashlib.sha256(event["event_id"].encode()).hexdigest()[:32]
                or payload["reason"] != RULES[event["kind"]][1]
                or payload["observed_at"] != event["detected_at"]
            ):
                raise ValueError("Review proposal differs from the audited application scope")
            try:
                signature = base64.b64decode(proposal["signature"], validate=True)
                observed, expires = (
                    datetime.fromisoformat(payload[k]) for k in ("observed_at", "expires_at")
                )
                if (
                    len(signature) != 64
                    or observed.tzinfo is None
                    or expires.tzinfo is None
                    or not observed < expires <= observed + timedelta(minutes=5)
                ):
                    raise ValueError()
            except (ValueError, TypeError):
                raise ValueError("Bounded signed review envelope required") from None
        # This transport checks audit binding. Intake independently authenticates
        # the registered detector key and current source revision before a hold.
        expected = "arn:aws:sqs:" + self.region + ":" + self.account + ":" + self.url.rsplit("/", 1)[-1]
        attrs = self.client.get_queue_attributes(
            QueueUrl=self.url, AttributeNames=["QueueArn", "SqsManagedSseEnabled"]
        )["Attributes"]
        tags = self.client.list_queue_tags(QueueUrl=self.url).get("Tags", {})
        if (
            attrs.get("QueueArn") != expected
            or attrs.get("SqsManagedSseEnabled") != "true"
            or tags.get("app") != "sky"
        ):
            raise ValueError("Review queue identity or encryption differs")
        response = self.client.send_message(
            QueueUrl=self.url,
            MessageBody=json.dumps(
                {
                    "version": 2,
                    "type": "security_review",
                    "signed_hold_proposal": result.get("signed_hold_proposal"),
                    "event": event,
                    "audit_sha256": result["audit"]["sha256"],
                    "automatic_release_permitted": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
        if not isinstance(response.get("MessageId"), str):
            raise OSError("Review notification result uncertain; do not clear security hold")
        return {"review_queued": True, "automatic_release_permitted": False}
