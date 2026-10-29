"""Audit-confirmed notifications use a dedicated queue, no app/log-selected endpoint."""

from unittest.mock import Mock

import pytest

from adapters.aws.security_review_queue import SecurityReviewQueue


def notifier():
    session = Mock()
    queue = SecurityReviewQueue(
        "https://sqs.ap-northeast-2.amazonaws.com/123456789012/sky-security-build-review",
        account_id="123456789012",
        region="ap-northeast-2",
        session=session,
    )
    queue.client.get_queue_attributes.return_value = {
        "Attributes": {
            "QueueArn": "arn:aws:sqs:ap-northeast-2:123456789012:sky-security-build-review",
            "SqsManagedSseEnabled": "true",
        }
    }
    queue.client.list_queue_tags.return_value = {"Tags": {"app": "sky"}}
    queue.client.send_message.return_value = {"MessageId": "synthetic"}
    return queue


def test_no_notification_before_append_only_audit():
    queue = notifier()
    with pytest.raises(ValueError):
        queue.notify({"event": {}, "audit": {}, "automatic_release_permitted": False})
    queue.client.send_message.assert_not_called()


def test_registered_machine_queue_receives_only_signed_app_scope():
    queue = notifier()
    import hashlib

    from adapters.aws.security_audit import audit_bytes
    from tests.unit.test_security_audit import sample

    fact = sample()
    value = {
        "event": fact,
        "audit": {
            "append_confirmed": True,
            "sha256": hashlib.sha256(
                audit_bytes(fact, fact["organization_id"], fact["application_id"])
            ).hexdigest(),
        },
        "signed_hold_proposal": {},
        "automatic_release_permitted": False,
    }
    assert queue.notify(value)["review_queued"]
    assert "automatic_release_permitted" in queue.client.send_message.call_args.kwargs["MessageBody"]
    queue.client.get_queue_attributes.return_value["Attributes"]["SqsManagedSseEnabled"] = "false"
    with pytest.raises(ValueError):
        queue.notify(value)
    assert queue.client.send_message.call_count == 1
