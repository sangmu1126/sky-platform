"""Audit metadata accepts no arbitrary source/log/Secret text or foreign app."""

from datetime import UTC, datetime
from unittest.mock import Mock
from uuid import uuid4

import pytest

from adapters.aws.security_audit import S3SecurityAudit


def sample():
    now = datetime.now(UTC).isoformat()
    return {
        "version": 1,
        "kind": "forbidden_secret_read",
        "severity": "critical",
        "event_id": str(uuid4()),
        "organization_id": "team",
        "application_id": "app",
        "job_id": "a" * 16,
        "source_digest": "b" * 64,
        "record_revision": 1,
        "detector_id": "collector",
        "observed_at": now,
        "detected_at": now,
        "evidence_digest": "c" * 64,
        "security_clearance": False,
    }


def audit():
    session = Mock()
    session.client.return_value.put_object.return_value = {"VersionId": "immutable-version"}
    return S3SecurityAudit(
        bucket="sky-security-test",
        account_id="123456789012",
        region="ap-northeast-2",
        organization_id="team",
        application_id="app",
        session=session,
    ), session.client.return_value


def test_append_requires_condition_version_and_registered_owner():
    service, client = audit()
    result = service.append(sample())
    args = client.put_object.call_args.kwargs
    assert args["IfNoneMatch"] == "*" and args["ExpectedBucketOwner"] == "123456789012"
    assert args["Key"].startswith("audit/team/app/") and result["append_confirmed"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", True),
        ("application_id", "foreign"),
        ("job_id", "private-secret"),
        ("source_digest", "private-secret"),
        ("record_revision", False),
        ("observed_at", "2026-10-30"),
        ("message", "private-secret"),
        ("severity", "safe"),
        ("security_clearance", True),
    ],
)
def test_unsafe_or_free_text_event_rejected_before_any_write(field, value):
    service, client = audit()
    event = sample()
    event[field] = value
    with pytest.raises(ValueError):
        service.append(event)
    client.put_object.assert_not_called()
