from unittest.mock import Mock

import pytest

from tests.unit.test_aws_incident_credentials import setup as preparation_setup
from tests.unit.test_aws_shared_database import ServiceError

OP = "a" * 32


def setup(monkeypatch):
    adapter, client, sql, _saved = preparation_setup(monkeypatch)
    adapter.prepare(OP, guard=Mock())
    describe = client.describe_secret.side_effect
    client.describe_secret.side_effect = lambda **kw: {
        **describe(**kw),
        "VersionIdsToStages": {OP: ["AWSCURRENT"]},
    }
    for name in (
        "create_secret",
        "put_resource_policy",
        "get_secret_value",
        "put_secret_value",
        "update_secret_version_stage",
        "delete_secret",
    ):
        method = getattr(client, name)
        method.reset_mock()
        method.side_effect = AssertionError("Mutation or password read")
    sql.prepare_password.reset_mock()
    sql.prepare_password.side_effect = AssertionError("SQL mutation")
    return adapter, client, sql


def assert_no_changes(client, sql):
    for name in (
        "create_secret",
        "put_resource_policy",
        "get_secret_value",
        "put_secret_value",
        "update_secret_version_stage",
        "delete_secret",
    ):
        getattr(client, name).assert_not_called()
    sql.prepare_password.assert_not_called()


def test_inspects_metadata_policy_and_native_db_without_reading_password(monkeypatch):
    adapter, client, sql = setup(monkeypatch)
    result = adapter.inspect(OP, guard=Mock())
    assert result["candidate_state"] == "registered_candidate" and result["candidate_version_id"] == OP
    assert result["password_update_verified"] is False and result["authentication_verified"] is False
    assert_no_changes(client, sql)


@pytest.mark.parametrize(
    "change,state",
    [
        ("missing", "not_found"),
        ("deleted", "scheduled_for_deletion"),
        ("version", "version_mismatch"),
        ("policy", "policy_unverified"),
        ("invalid-policy", "policy_unverified"),
    ],
)
def test_partial_candidate_is_reported_without_adoption(monkeypatch, change, state):
    adapter, client, sql = setup(monkeypatch)
    describe = client.describe_secret.side_effect
    if change == "missing":
        client.describe_secret.side_effect = ServiceError("ResourceNotFoundException")
    elif change == "deleted":
        client.describe_secret.side_effect = lambda **kw: {**describe(**kw), "DeletedDate": "scheduled"}
    elif change == "version":
        client.describe_secret.side_effect = lambda **kw: {
            **describe(**kw),
            "VersionIdsToStages": {"other": ["AWSCURRENT"]},
        }
    elif change == "policy":
        client.get_resource_policy.side_effect = lambda **kw: {}
    else:
        client.get_resource_policy.side_effect = lambda **kw: {"ResourcePolicy": "malformed"}
    result = adapter.inspect(OP, guard=Mock())
    assert result["candidate_state"] == state and result["candidate_version_id"] is None
    assert_no_changes(client, sql)


@pytest.mark.parametrize("change", ["access", "owner", "key", "arn"])
def test_denied_or_foreign_metadata_never_becomes_absent_or_valid(monkeypatch, change):
    adapter, client, sql = setup(monkeypatch)
    describe = client.describe_secret.side_effect
    if change == "access":
        client.describe_secret.side_effect = ServiceError("AccessDeniedException")
    elif change == "owner":
        client.describe_secret.side_effect = lambda **kw: {**describe(**kw), "Tags": []}
    elif change == "key":
        client.describe_secret.side_effect = lambda **kw: {**describe(**kw), "KmsKeyId": "foreign"}
    else:
        client.describe_secret.side_effect = lambda **kw: {**describe(**kw), "ARN": "foreign"}
    with pytest.raises((ValueError, ServiceError)):
        adapter.inspect(OP, guard=Mock())
    assert_no_changes(client, sql)
