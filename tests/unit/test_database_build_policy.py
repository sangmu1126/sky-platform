"""Database opt-in cannot erase unsupported requirements or foreign ownership."""

import json
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from application.database_build_policy import DatabaseBuildPolicy
from domain.access import LoginSource, Principal, Role

NOW = datetime(2026, 10, 30, tzinfo=UTC)


def policy(**changes):
    values = {
        "account_id": "265233844540",
        "region": "ap-northeast-2",
        "organization_id": "personal",
        "allowed_users": ("owner",),
        "pool_id": "personal-pool",
        "instance_id": "sky-personal-workload-pool",
        "configuration_digest": "a" * 64,
        "expires_at": (NOW + timedelta(hours=12)).isoformat(),
    }
    return DatabaseBuildPolicy(**(values | changes))


def principal(user="owner", org="personal"):
    return Principal(user, org, Role.DEPLOYER, LoginSource.EXTERNAL_IDP)


def test_only_managed_environment_blockers_are_discharged_and_evidence_remains():
    p = policy()
    plan = {"required_env": ["PGHOST", "PGPASSWORD"], "evidence": ["app.py"]}
    inspection = {
        "requirements": ["database"],
        "database_engines": ["postgresql"],
        "evidence_files": ["app.py"],
    }
    blockers = [
        {"code": x}
        for x in (
            "infrastructure_preparation_required",
            "environment_binding_required",
            "independent_unresolved",
        )
    ]
    assert p.apply(principal(), plan, inspection, blockers, now=NOW) == [{"code": "independent_unresolved"}]
    assert plan["infrastructure_profile"]["requirements"] == ["database"]
    assert inspection["evidence_files"] == ["app.py"] and plan["evidence"] == ["app.py"]
    assert "password" not in json.dumps(p.binding()).lower()
    request = {"created_by": "owner", "account_id": p.account_id, "region": p.region}
    p.authorize(request, SimpleNamespace(organization_id="personal"), plan, now=NOW)
    for key, value in (("created_by", "foreign"), ("account_id", "000000000000"), ("region", "us-east-1")):
        with pytest.raises(PermissionError):
            p.authorize(request | {key: value}, SimpleNamespace(organization_id="personal"), plan, now=NOW)
    with pytest.raises(PermissionError):
        p.authorize(request, SimpleNamespace(organization_id="personal"), plan, now=NOW + timedelta(days=1))


@pytest.mark.parametrize(
    "user,org,requirements,engines,env,expired",
    [
        ("foreign", "personal", ["database"], ["postgresql"], ["PGHOST"], False),
        ("owner", "foreign", ["database"], ["postgresql"], ["PGHOST"], False),
        ("owner", "personal", ["database", "worker"], ["postgresql"], ["PGHOST"], False),
        ("owner", "personal", ["sqlite"], ["sqlite"], ["PGHOST"], False),
        ("owner", "personal", ["database"], ["mysql"], ["PGHOST"], False),
        ("owner", "personal", ["database"], ["postgresql"], ["API_KEY"], False),
        ("owner", "personal", ["database"], ["postgresql"], ["PGHOST"], True),
    ],
)
def test_unsupported_or_untrusted_cases_remain_blocked(user, org, requirements, engines, env, expired):
    p = policy(expires_at=(NOW - timedelta(seconds=1)).isoformat()) if expired else policy()
    plan = {"required_env": env}
    inspection = {"requirements": requirements, "database_engines": engines}
    blockers = [{"code": "infrastructure_preparation_required"}, {"code": "environment_binding_required"}]
    assert p.apply(principal(user, org), plan, inspection, blockers, now=NOW) == blockers
    assert "database_profile" not in plan


def test_policy_json_roundtrip_and_unexpected_fields_rejected():
    p = policy()
    assert DatabaseBuildPolicy.load(json.dumps({"version": 1, **asdict(p)})) == p
    with pytest.raises((TypeError, ValueError)):
        DatabaseBuildPolicy.load(json.dumps({"version": 1, **asdict(p), "secret": "not-accepted"}))
    with pytest.raises(ValueError):
        DatabaseBuildPolicy.load("x" * 8193)


def test_pg8000_manifest_and_source_remain_database_requirements(tmp_path):
    from application.infrastructure import inspect_infrastructure

    (tmp_path / "app.py").write_text("import pg8000.native\n")
    profile = inspect_infrastructure(tmp_path)
    assert profile.requirements == ("database",) and profile.database_engines == ("postgresql",)
