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
        from adapters.aws.security_audit import audit_bytes
        import hashlib

        raw = audit_bytes(event, event.get("organization_id"), event.get("application_id"))
        if result["audit"].get("sha256") != hashlib.sha256(raw).hexdigest():
            raise ValueError("Notification differs from the independently stored audit fact")
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
                    "version": 1,
                    "type": "security_review",
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
