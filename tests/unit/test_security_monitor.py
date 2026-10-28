"""Only AWS events bound to exact account/role ID/Secret are relevant evidence."""

import json
from copy import deepcopy
from unittest.mock import Mock
from uuid import uuid4

import pytest

from adapters.aws.security_monitor import CloudTrailSecretAccessMonitor, SecretAccessRegistration


@pytest.fixture
def monitor():
    role = "arn:aws:iam::111111111111:role/app"
    secret = "arn:aws:secretsmanager:ap-northeast-2:111111111111:secret:pool-admin-Abc123"
    registration = SecretAccessRegistration(
        "111111111111", "ap-northeast-2", role, "AROA" + "A" * 17, (secret,)
    )
    session = Mock()
    sts, trail = Mock(), Mock()
    sts.get_caller_identity.return_value = {"Account": "111111111111"}
    session.client.side_effect = lambda name, **_: {"sts": sts, "cloudtrail": trail}[name]
    event = {
        "eventSource": "secretsmanager.amazonaws.com",
        "eventName": "GetSecretValue",
        "recipientAccountId": "111111111111",
        "awsRegion": "ap-northeast-2",
        "eventID": str(uuid4()),
        "eventTime": "2026-10-29T00:00:00Z",
        "requestParameters": {"secretId": secret},
        "userIdentity": {
            "type": "AssumedRole",
            "principalId": registration.role_id + ":session",
            "sessionContext": {"sessionIssuer": {"arn": role}},
        },
    }
    return CloudTrailSecretAccessMonitor(registration, session=session), trail, event


def test_successful_forbidden_read_is_observation_not_automatic_hold(monitor):
    service, trail, event = monitor
    trail.lookup_events.return_value = {"Events": [{"CloudTrailEvent": json.dumps(event)}]}
    value = service.observe(now="2026-10-29T00:01:00+00:00")
    assert value["matching_successful_forbidden_reads"] == [event["eventID"]]
    assert value["requires_operator_review"] and not value["automatic_hold_executed"]
    assert event["requestParameters"]["secretId"] not in json.dumps(value)


@pytest.mark.parametrize(
    "field,value",
    [("recipientAccountId", "222222222222"), ("awsRegion", "us-east-1"), ("eventName", "DescribeSecret")],
)
def test_other_scopes_are_not_incident_evidence(monitor, field, value):
    service, trail, event = monitor
    event[field] = value
    trail.lookup_events.return_value = {"Events": [{"CloudTrailEvent": json.dumps(event)}]}
    result = service.observe(now="2026-10-29T00:01:00+00:00")
    assert not result["requires_operator_review"]
    assert not result["absence_of_compromise_proven"]


def test_denial_and_recreated_role_identity_are_distinguished(monitor):
    service, trail, event = monitor
    denied = deepcopy(event)
    denied["errorCode"] = "AccessDenied"
    recreated = deepcopy(event)
    recreated["userIdentity"]["principalId"] = "AROA" + "B" * 17 + ":session"
    trail.lookup_events.return_value = {
        "Events": [{"CloudTrailEvent": json.dumps(item)} for item in (denied, recreated)]
    }
    result = service.observe(now="2026-10-29T00:01:00+00:00")
    assert result["matching_denied_reads"] == 1
    assert not result["matching_successful_forbidden_reads"]


def test_truncated_collection_is_never_a_clean_result(monitor):
    service, trail, _ = monitor
    trail.lookup_events.return_value = {"Events": [], "NextToken": "more"}
    result = service.observe(now="2026-10-29T00:01:00+00:00")
    assert trail.lookup_events.call_count == 3 and not result["collection_complete"]
    assert not result["absence_of_compromise_proven"]
