import json
from dataclasses import asdict
from unittest.mock import Mock

import pytest

from adapters.aws.incident_credentials import AwsIncidentCredentialPreparation
from adapters.database.incident_restriction import PostgresIncidentRestriction
from adapters.database.promotion_fence import PostgresApplicationFence
from domain.database import DatabaseBinding


def setup(monkeypatch):
    binding = DatabaseBinding(
        "org", "game", "shared_workload", "111111111111", "ap-northeast-2", "pool", "game", "owner"
    )
    fence = Mock(spec=PostgresApplicationFence, binding=binding, role="sky_login_test")
    fence.inspect.return_value = {
        "binding": asdict(binding),
        "login_enabled": False,
        "active_sessions": 0,
        "read_only": True,
    }
    restriction = PostgresIncidentRestriction(fence)
    client = Mock()
    client.meta.region_name = binding.region
    key = f"arn:aws:kms:{binding.region}:{binding.account_id}:key/11111111-1111-1111-1111-111111111111"
    saved = {}

    def create(**kwargs):
        saved.update(kwargs)
        arn = f"arn:aws:secretsmanager:{binding.region}:{binding.account_id}:secret:{kwargs['Name']}-test01"
        saved["arn"] = arn
        return {"ARN": arn, "VersionId": kwargs["ClientRequestToken"]}

    client.create_secret.side_effect = create
    client.describe_secret.side_effect = lambda **kw: {
        "ARN": saved["arn"],
        "Name": saved["Name"],
        "KmsKeyId": key,
        "Tags": saved["Tags"],
    }
    client.put_resource_policy.side_effect = lambda **kw: saved.update(policy=kw["ResourcePolicy"])
    client.get_resource_policy.side_effect = lambda **kw: {"ResourcePolicy": saved["policy"]}
    client.get_secret_value.side_effect = lambda **kw: {
        "ARN": saved["arn"],
        "VersionId": saved["ClientRequestToken"],
        "VersionStages": ["AWSCURRENT"],
        "SecretString": saved["SecretString"],
    }
    sql = Mock()
    sql.prepare_password.return_value = {
        "binding": asdict(binding),
        "password_update_acknowledged": True,
        "login_enabled": False,
        "active_sessions": 0,
        "authentication_verified": False,
    }
    monkeypatch.setattr(
        "adapters.aws.incident_credentials.PostgresIncidentCredentialPreparation", Mock(return_value=sql)
    )
    return (
        AwsIncidentCredentialPreparation(
            restriction,
            resource_id="db-TEST",
            kms_key_arn=key,
            principal_arn=f"arn:aws:iam::{binding.account_id}:user/preparer",
            client=client,
        ),
        client,
        sql,
        saved,
    )


def test_new_secret_and_sql_do_not_change_old_secret_or_grant_access(monkeypatch):
    adapter, client, sql, saved = setup(monkeypatch)
    result = adapter.prepare("a" * 32, guard=Mock())
    assert saved["Name"] == "sky-incident/db-TEST/" + "a" * 32
    password = json.loads(saved["SecretString"])["password"]
    assert len(password) >= 32 and password not in json.dumps(result)
    assert sql.prepare_password.call_args.args == (password,)
    assert result["authentication_verified"] is False and result["runtime_access_granted"] is False
    client.put_secret_value.assert_not_called()
    client.update_secret_version_stage.assert_not_called()
    client.delete_secret.assert_not_called()


@pytest.mark.parametrize(
    "change",
    ["login", "sessions", "unknown-create", "existing-name", "metadata", "policy", "version", "value"],
)
def test_unsafe_or_uncertain_candidate_never_updates_password(monkeypatch, change):
    adapter, client, sql, saved = setup(monkeypatch)
    if change == "login":
        adapter.restriction.fence.inspect.return_value["login_enabled"] = True
    elif change == "sessions":
        adapter.restriction.fence.inspect.return_value["active_sessions"] = 1
    elif change in {"unknown-create", "existing-name"}:
        client.create_secret.side_effect = OSError("unknown secret result")
    elif change == "metadata":
        client.describe_secret.side_effect = lambda **kw: {"ARN": "foreign"}
    elif change == "policy":
        client.get_resource_policy.side_effect = lambda **kw: {"ResourcePolicy": "{}"}
    elif change == "version":
        client.get_secret_value.side_effect = lambda **kw: {"VersionId": "foreign"}
    else:
        client.get_secret_value.side_effect = lambda **kw: {
            "ARN": saved["arn"],
            "VersionId": "a" * 32,
            "VersionStages": ["AWSCURRENT"],
            "SecretString": "{}",
        }
    with pytest.raises((ValueError, OSError)):
        adapter.prepare("a" * 32, guard=Mock())
    sql.prepare_password.assert_not_called()
    assert client.create_secret.call_count <= 1


def test_guard_revocation_before_creation_prevents_secret_write(monkeypatch):
    adapter, client, sql, _ = setup(monkeypatch)
    with pytest.raises(PermissionError):
        adapter.prepare("a" * 32, guard=Mock(side_effect=PermissionError("revoked")))
    client.create_secret.assert_not_called()
    sql.prepare_password.assert_not_called()


def test_stable_assumed_role_principal_is_verified_with_iam_role_id():
    from adapters.aws.incident_credentials import credential_preparation_principal

    binding = DatabaseBinding(
        "org", "game", "dedicated_workload", "111111111111", "ap-northeast-2", "db", "game", "owner"
    )
    sts, iam = Mock(), Mock()
    sts.get_caller_identity.return_value = {
        "Account": binding.account_id,
        "Arn": "arn:aws:sts::111111111111:assumed-role/preparer/session",
        "UserId": "AROAEXAMPLE:session",
    }
    iam.get_role.return_value = {
        "Role": {
            "Arn": "arn:aws:iam::111111111111:role/path/preparer",
            "RoleName": "preparer",
            "RoleId": "AROAEXAMPLE",
        }
    }
    session = Mock()
    session.client.side_effect = lambda name, **kw: {"sts": sts, "iam": iam}[name]
    assert (
        credential_preparation_principal(session, binding) == "arn:aws:iam::111111111111:role/path/preparer"
    )
    iam.get_role.return_value["Role"]["RoleId"] = "AROAOTHER"
    with pytest.raises(ValueError):
        credential_preparation_principal(session, binding)
    sts.get_caller_identity.return_value["Account"] = "222222222222"
    with pytest.raises(ValueError):
        credential_preparation_principal(session, binding)


def test_candidate_policy_denies_all_other_principals_before_password_update(monkeypatch):
    adapter, client, sql, saved = setup(monkeypatch)
    adapter.prepare("a" * 32, guard=Mock())
    policy = json.loads(saved["policy"])
    statement = policy["Statement"][0]
    assert statement["Effect"] == "Deny" and statement["Principal"] == "*"
    assert statement["Action"] == "secretsmanager:*"
    assert statement["Condition"] == {"ArnNotEquals": {"aws:PrincipalArn": adapter.principal_arn}}
    assert client.put_resource_policy.call_args.kwargs["BlockPublicPolicy"] is True
    sql.prepare_password.assert_called_once()
