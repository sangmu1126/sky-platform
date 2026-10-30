"""DB preparation journals before effects and refuses swapped receipts/roles."""

import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from adapters.aws.hosted_database_build import HostedDatabaseBuild
from adapters.database.migrations import trusted_rds_ca_bundle
from application.database_build_policy import DatabaseBuildPolicy
from domain.shared_database import SharedDatabasePool
from ports.remote_builds import digest
from tests.unit.test_built_deployment import prepared as prepared  # noqa: PLC0414


@pytest.fixture
def database_build(prepared, tmp_path):
    adapter, request, _ = prepared
    plan = json.loads(request["approved_plan_json"])
    policy = DatabaseBuildPolicy(
        adapter.settings.account_id,
        adapter.settings.region,
        "team",
        ("alice",),
        "personal",
        "sky-pool",
        "a" * 64,
        (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    )
    plan.update(
        database_profile="shared-postgres-v1",
        database_pool_registration=policy.binding(),
        required_env=["PGHOST"],
        infrastructure_profile={"requirements": ["database"], "database_engines": ["postgresql"]},
    )
    request = {
        **request,
        "created_by": "alice",
        "approved_plan_json": json.dumps(plan, sort_keys=True, separators=(",", ":")),
        "plan_digest": digest(plan),
    }
    pool = SharedDatabasePool(
        "personal", policy.account_id, policy.region, "sky-pool", "sky_pool_personal", 20
    )
    allocator = Mock()
    allocator.settings = SimpleNamespace(
        pool=pool, vpc_id="vpc-" + "a" * 17, allowed_client_groups=("sg-" + "b" * 17,)
    )
    allocator.inspect_allocation.return_value = {
        "secret_ref": f"arn:aws:secretsmanager:{policy.region}:{policy.account_id}:secret:sky-pool/personal/synthetic-Abc123",
        "kms_key_arn": f"arn:aws:kms:{policy.region}:{policy.account_id}:key/00000000-0000-0000-0000-000000000000",
        "host": "synthetic.rds.amazonaws.com",
        "port": 5432,
    }
    (tmp_path / "migrations").mkdir()
    (tmp_path / "migrations/0001_rows.sql").write_text("CREATE TABLE rows(id integer);")
    (tmp_path / ".sky-rds-ca.pem").write_bytes(trusted_rds_ca_bundle().read_bytes())
    sources = Mock()

    @contextmanager
    def restore(*_):
        yield tmp_path

    sources.restore.side_effect = restore
    objects = Mock()
    iam = Mock()
    logs = Mock()
    session = Mock()
    session.client.side_effect = lambda name, **_: {"iam": iam, "logs": logs}[name]
    boundary = f"arn:aws:iam::{policy.account_id}:policy/sky-personal-workload-execution-boundary"
    role = {
        "Arn": f"arn:aws:iam::{policy.account_id}:role/sky-workload-" + request["job_id"],
        "RoleId": "AROA" + "A" * 17,
        "PermissionsBoundary": {"PermissionsBoundaryArn": boundary},
    }
    iam.create_role.return_value = {"Role": role}
    iam.get_role.return_value = {"Role": role}
    service = HostedDatabaseBuild(
        policy,
        allocator,
        sources,
        objects,
        adapter.settings,
        security_group="sg-" + "b" * 17,
        subnets=["subnet-" + "c" * 17, "subnet-" + "d" * 17],
        boundary_arn=boundary,
        session=session,
    )
    return service, request, tmp_path, iam, objects


def test_preparation_persists_before_allocation_and_only_publishes_reference_receipt(database_build):
    service, request, _, iam, objects = database_build
    saved = []

    def persist(value):
        saved.append(json.loads(json.dumps(value)))

    service.allocator.allocate.side_effect = lambda *_: (
        saved[-1]["database_preparation"]["stage"] == "allocating" or pytest.fail("effect without intent")
    )
    with patch(
        "adapters.aws.hosted_database_build.apply_hosted_migrations",
        return_value={"protocol": "app-role-schema-v1", "bundle_digest": "c" * 64},
    ):
        service.prepare(request, {"stage": "building"}, lambda: None, persist)
    receipt = objects.put.call_args.args[1]
    assert [x["database_preparation"]["stage"] for x in saved] == [
        "allocating",
        "schema",
        "execution_identity",
        "prepared",
    ]
    assert "password" not in json.dumps(receipt).lower()
    assert iam.create_role.call_args.kwargs["PermissionsBoundary"] == service.boundary_arn
    objects.read.return_value = receipt
    assert service.for_request(request, lambda: None).job == request["job_id"]
    for field, value in [
        ("request_digest", "f" * 64),
        ("role_id", "AROA" + "B" * 17),
        ("binding", {}),
        ("execution_boundary_arn", "foreign"),
    ]:
        objects.read.return_value = {**receipt, field: value}
        with pytest.raises((ValueError, PermissionError)):
            service.for_request(request, lambda: None)


def test_untrusted_owner_or_changed_ca_prevents_database_effect(database_build):
    service, request, project, _, _ = database_build
    with pytest.raises(PermissionError):
        service.prepare({**request, "created_by": "mallory"}, {}, lambda: None, Mock())
    (project / ".sky-rds-ca.pem").write_text("untrusted certificate")
    with pytest.raises(ValueError, match="trust bundle"):
        service.prepare(request, {}, lambda: None, Mock())
    service.allocator.allocate.assert_not_called()


def test_schema_error_keeps_intent_without_role_or_dispatch(database_build):
    service, request, _, iam, objects = database_build
    saved = []
    with (
        patch(
            "adapters.aws.hosted_database_build.apply_hosted_migrations",
            side_effect=OSError("uncertain migration"),
        ),
        pytest.raises(OSError),
    ):
        service.prepare(request, {}, lambda: None, saved.append)
    assert saved[-1]["database_preparation"]["stage"] == "schema"
    iam.create_role.assert_not_called()
    objects.put.assert_not_called()
