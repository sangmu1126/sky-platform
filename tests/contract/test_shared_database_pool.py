"""Real logical DB isolation on a disposable, separate workload PostgreSQL."""

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from unittest.mock import patch

import pytest

psycopg = pytest.importorskip("psycopg")
from psycopg import sql

from adapters.database.shared_pool import PostgresSharedPool
from domain.shared_database import PoolAllocationRequest, SharedDatabasePool
from engine.database_promotion import DatabaseBinding, PromotionTrigger, plan_database_promotion
from ports.shared_database import (
    AllocationCredentials,
    PoolAllocationConflict,
    PoolAllocationError,
    PoolCapacityExceeded,
)


@pytest.fixture
def database():
    dsn = os.environ.get("SKY_TEST_POOL_POSTGRES_DSN")
    if not dsn:
        pytest.skip("Separate disposable workload PostgreSQL DSN required")
    params = psycopg.conninfo.conninfo_to_dict(dsn)
    if params.get("host") not in {"127.0.0.1", "localhost", "::1"} or not params.get("dbname", "").startswith(
        "sky_pool_"
    ):
        pytest.fail("Only a loopback workload pool control DB is allowed")
    settings = SharedDatabasePool(
        "contract", "111111111111", "ap-northeast-2", "disposable-pool", params["dbname"], 30
    )

    def admin(name):
        return psycopg.connect(
            **{**params, "dbname": name}, options="-c statement_timeout=30000 -c lock_timeout=10000"
        )

    def application(name, role, password):
        return psycopg.connect(**{**params, "dbname": name, "user": role, "password": password})

    adapter = PostgresSharedPool(settings, admin, application)
    adapter.initialize()
    yield adapter, admin, application
    with admin(settings.control_database) as connection:
        connection.autocommit = True
        allocations = connection.execute("SELECT request FROM sky_pool.allocations").fetchall()
        for (request,) in allocations:
            name, role = request["database_name"], request["login_role"]
            assert name.startswith("sky_app_") and role.startswith("sky_login_")
            connection.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
            )
        for (request,) in allocations:
            connection.execute(
                sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(request["login_role"]))
            )
        connection.execute("DELETE FROM sky_pool.allocations")


def credentials(request):
    reference = f"arn:aws:secretsmanager:{request.pool.region}:{request.pool.account_id}:secret:sky-pool/{request.pool.id}/{request.id}-test01"
    return AllocationCredentials(reference, "disposable-pool-password-for-test")


def test_timeout_defaults_are_not_misrepresented_as_hostile_tenant_isolation(database):
    adapter, _admin, application = database
    allocation = PoolAllocationRequest(adapter.pool, "team", "timeout-test")
    adapter.allocate(allocation, credentials(allocation))
    with application(allocation.database_name, allocation.login_role, credentials(allocation).password) as db:
        assert db.execute("SHOW statement_timeout").fetchone() == ("30s",)
        assert db.execute("SHOW lock_timeout").fetchone() == ("5s",)
        assert db.execute("SHOW idle_in_transaction_session_timeout").fetchone() == ("1min",)
        db.execute("SET statement_timeout=0")
        assert db.execute("SHOW statement_timeout").fetchone() == ("0",)
        # Record the real bypass capability rather than treating role defaults
        # as enforced protection against an adversarial app.


def test_bounded_busy_neighbor_preserves_other_app_reads_and_acl(database):
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor

    adapter, _admin, application = database
    first = PoolAllocationRequest(adapter.pool, "team-a", "busy-app")
    second = PoolAllocationRequest(adapter.pool, "team-b", "neighbor")
    for allocation in (first, second):
        adapter.allocate(allocation, credentials(allocation))
    with application(second.database_name, second.login_role, credentials(second).password) as db:
        db.execute("CREATE TABLE neighbor_data(id integer PRIMARY KEY)")
        db.execute("INSERT INTO neighbor_data VALUES(1)")
    started_query = threading.Event()

    def busy():
        with application(first.database_name, first.login_role, credentials(first).password) as db:
            db.execute("SET statement_timeout='150ms'")
            started_query.set()
            with pytest.raises(psycopg.errors.QueryCanceled):
                db.execute("SELECT pg_sleep(2)")

    samples = []
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(busy)
        assert started_query.wait(timeout=5)
        for _ in range(3):
            started = time.monotonic()
            with application(second.database_name, second.login_role, credentials(second).password) as db:
                assert db.execute("SELECT id FROM neighbor_data").fetchone() == (1,)
            samples.append(time.monotonic() - started)
        future.result(timeout=5)
    with pytest.raises(psycopg.OperationalError):
        application(second.database_name, first.login_role, credentials(first).password)
    # Functional check under a bounded sleep only; no CPU/IO isolation assertion.
    assert len(samples) == 3 and all(sample >= 0 for sample in samples)


def test_two_apps_can_write_own_tables_but_cannot_connect_to_each_other(database):
    adapter, admin, application = database
    first = PoolAllocationRequest(adapter.pool, "team-a", "game")
    second = PoolAllocationRequest(adapter.pool, "team-b", "game")
    first_result = adapter.allocate(first, credentials(first))
    adapter.allocate(second, credentials(second))
    with application(first.database_name, first.login_role, credentials(first).password) as connection:
        connection.execute("CREATE TABLE scores(id integer PRIMARY KEY, score integer)")
        connection.execute("INSERT INTO scores VALUES (1, 42)")
    for name in (second.database_name, adapter.pool.control_database, "postgres"):
        with pytest.raises(psycopg.OperationalError):
            application(name, first.login_role, credentials(first).password)
    with application(first.database_name, first.login_role, credentials(first).password) as connection:
        assert connection.execute("SELECT score FROM scores WHERE id=1").fetchone() == (42,)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            connection.execute("CREATE ROLE forbidden")
    with admin(adapter.pool.control_database) as connection:
        assert credentials(first).password not in str(
            connection.execute("SELECT request FROM sky_pool.allocations").fetchall()
        )
    assert first_result["verified_scope"] == "postgresql_role_and_database_acl"
    target = replace(
        DatabaseBinding(**first_result["binding"]), role="dedicated_workload", instance_id="dedicated-game"
    )
    plan = plan_database_promotion(
        DatabaseBinding(**first_result["binding"]),
        target,
        PromotionTrigger("scheduled_review", "policy-1", "observation-1", "2026-10-11T00:00:00+09:00"),
        source_revision="a" * 64,
    )
    assert plan["ready_to_cutover"] is False


def test_concurrent_retries_share_one_allocation_and_preserve_data(database):
    adapter, admin, application = database
    request = PoolAllocationRequest(adapter.pool, "team-a", "game")
    with ThreadPoolExecutor(max_workers=4) as workers:
        receipts = list(workers.map(lambda _: adapter.allocate(request, credentials(request)), range(6)))
    assert {receipt["allocation_id"] for receipt in receipts} == {request.id}
    with application(request.database_name, request.login_role, credentials(request).password) as connection:
        connection.execute("CREATE TABLE retained(id integer)")
        connection.execute("INSERT INTO retained VALUES (7)")
    PostgresSharedPool(adapter.pool, admin, application).allocate(request, credentials(request))
    with application(request.database_name, request.login_role, credentials(request).password) as connection:
        assert connection.execute("SELECT id FROM retained").fetchall() == [(7,)]
    with pytest.raises(PoolAllocationConflict):
        adapter.allocate(replace(request, connection_limit=10), credentials(request))


def test_budget_exhaustion_has_no_new_db_and_uncertain_effects_are_preserved(database):
    adapter, admin, _ = database
    first = PoolAllocationRequest(adapter.pool, "team-a", "first", 30)
    adapter.allocate(first, credentials(first))
    other = PoolAllocationRequest(adapter.pool, "team-a", "other")
    with pytest.raises(PoolCapacityExceeded):
        adapter.allocate(other, credentials(other))
    with admin(adapter.pool.control_database) as connection:
        assert not connection.execute(
            "SELECT 1 FROM pg_database WHERE datname=%s", (other.database_name,)
        ).fetchone()
    with (
        patch.object(adapter, "_verify", side_effect=OSError("uncertain probe")),
        pytest.raises(PoolAllocationError),
    ):
        adapter.allocate(first, credentials(first))
    with pytest.raises(PoolAllocationError, match="reconciliation"):
        adapter.allocate(first, credentials(first))
    with admin(adapter.pool.control_database) as connection:
        assert connection.execute(
            "SELECT state FROM sky_pool.allocations WHERE id=%s", (first.id,)
        ).fetchone() == ("needs_attention",)
        assert connection.execute(
            "SELECT 1 FROM pg_database WHERE datname=%s", (first.database_name,)
        ).fetchone()


def test_privilege_drift_and_state_db_reuse_are_blocked(database):
    adapter, admin, _ = database
    request = PoolAllocationRequest(adapter.pool, "team-a", "game")
    adapter.allocate(request, credentials(request))
    with admin(adapter.pool.control_database) as connection:
        connection.execute(sql.SQL("ALTER ROLE {} CREATEDB").format(sql.Identifier(request.login_role)))
    with pytest.raises(PoolAllocationConflict):
        adapter.allocate(request, credentials(request))
    with admin(adapter.pool.control_database) as connection:
        connection.execute("CREATE SCHEMA sky_state")
    try:
        with pytest.raises(PoolAllocationError, match="Sky state"):
            adapter.initialize()
    finally:
        with admin(adapter.pool.control_database) as connection:
            connection.execute("DROP SCHEMA sky_state")


def test_deleted_ready_database_is_not_recreated_as_empty_success(database):
    adapter, admin, _ = database
    request = PoolAllocationRequest(adapter.pool, "team-a", "game")
    adapter.allocate(request, credentials(request))
    with admin(adapter.pool.control_database) as connection:
        connection.autocommit = True
        connection.execute(
            sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(request.database_name))
        )
    with pytest.raises(PoolAllocationConflict, match="missing"):
        adapter.allocate(request, credentials(request))
    with admin(adapter.pool.control_database) as connection:
        assert not connection.execute(
            "SELECT 1 FROM pg_database WHERE datname=%s", (request.database_name,)
        ).fetchone()


def test_named_cross_tenant_grant_blocks_further_allocations(database):
    adapter, admin, _ = database
    first = PoolAllocationRequest(adapter.pool, "team-a", "game")
    second = PoolAllocationRequest(adapter.pool, "team-b", "game")
    adapter.allocate(first, credentials(first))
    adapter.allocate(second, credentials(second))
    with admin(adapter.pool.control_database) as connection:
        connection.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                sql.Identifier(first.database_name), sql.Identifier(second.login_role)
            )
        )
    with pytest.raises(PoolAllocationError, match="another"):
        adapter.allocate(first, credentials(first))


def test_provider_database_is_never_adopted_as_an_application_database(database):
    adapter, admin, application = database
    with admin(adapter.pool.control_database) as connection:
        connection.autocommit = True
        connection.execute("CREATE ROLE rdsadmin SUPERUSER NOLOGIN")
        connection.execute("CREATE DATABASE rdsadmin OWNER rdsadmin TEMPLATE template0")
        connection.execute("REVOKE CONNECT ON DATABASE rdsadmin FROM PUBLIC")
    try:
        with pytest.raises(PoolAllocationError, match="Unregistered database"):
            adapter.check_registration()
        managed = PostgresSharedPool(adapter.pool, admin, application, rds_managed=True)
        managed.check_registration()
        request = PoolAllocationRequest(adapter.pool, "team-a", "game")
        managed.allocate(request, credentials(request))
        with pytest.raises(psycopg.OperationalError):
            application("rdsadmin", request.login_role, credentials(request).password)
        with admin(adapter.pool.control_database) as connection:
            connection.execute("GRANT CONNECT ON DATABASE rdsadmin TO PUBLIC")
        with pytest.raises(PoolAllocationError, match="PUBLIC database"):
            managed.check_registration()
    finally:
        with admin(adapter.pool.control_database) as connection:
            connection.autocommit = True
            connection.execute("DROP DATABASE rdsadmin WITH (FORCE)")
            connection.execute("DROP ROLE rdsadmin")


def test_existing_allocation_lookup_is_read_only_and_accepts_restricted_role(database):
    adapter, admin, _ = database
    request = PoolAllocationRequest(adapter.pool, "team-a", "game", 7)
    adapter.allocate(request, credentials(request))
    with admin(adapter.pool.control_database) as connection:
        connection.execute(sql.SQL("ALTER ROLE {} NOLOGIN").format(sql.Identifier(request.login_role)))
        before = connection.execute("SELECT request,state FROM sky_pool.allocations").fetchall()
    original = adapter._registration

    def prove_read_only(connection):
        assert connection.execute("SHOW transaction_read_only").fetchone() == ("on",)
        original(connection)
        # A write would be refused by PostgreSQL, not just by adapter convention.
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction), connection.transaction():
            connection.execute("UPDATE sky_pool.allocations SET state='needs_attention'")

    with patch.object(adapter, "_registration", side_effect=prove_read_only):
        assert adapter.existing_allocation(request.binding()) == request
    with admin(adapter.pool.control_database) as connection:
        assert connection.execute("SELECT request,state FROM sky_pool.allocations").fetchall() == before
        assert connection.execute(
            "SELECT rolcanlogin FROM pg_roles WHERE rolname=%s", (request.login_role,)
        ).fetchone() == (False,)


@pytest.mark.parametrize("change", ["missing", "pending", "payload", "role", "marker", "foreign-binding"])
def test_existing_allocation_rejects_unregistered_or_changed_identity(database, change):
    adapter, admin, _ = database
    request = PoolAllocationRequest(adapter.pool, "team-a", "game")
    binding = request.binding()
    if change != "missing":
        adapter.allocate(request, credentials(request))
    with admin(adapter.pool.control_database) as connection:
        if change == "pending":
            connection.execute("UPDATE sky_pool.allocations SET state='provisioning'")
        elif change == "payload":
            connection.execute(
                'UPDATE sky_pool.allocations SET request=request || \'{"application_id":"other"}\'::jsonb'
            )
        elif change == "role":
            connection.execute(sql.SQL("ALTER ROLE {} CREATEDB").format(sql.Identifier(request.login_role)))
        elif change == "marker":
            connection.execute(
                sql.SQL("COMMENT ON ROLE {} IS 'foreign'").format(sql.Identifier(request.login_role))
            )
        elif change == "foreign-binding":
            binding = replace(binding, instance_id="other-instance")
    with pytest.raises(PoolAllocationError):
        adapter.existing_allocation(binding)


def test_operator_cli_restricts_and_inspects_only_registered_database(
    database, tmp_path, monkeypatch, capsys
):
    """Real SQL/fence + CLI; AWS identity/secret/TLS and state store are doubles here."""
    import json
    from dataclasses import asdict
    from unittest.mock import Mock

    from adapters.aws.shared_database import AwsSharedDatabaseAllocator
    from application.security_hold import SecurityHold
    from domain.access import Role
    from interfaces.b_runtime import main
    from interfaces.shared_database_worker import load_pool_configuration
    from tests.unit.test_deployment_writes import Records, principal
    from tests.unit.test_incident_database_cli import command
    from tests.unit.test_security_hold_cli import ISSUER, arguments

    allocator, admin, application = database
    request = PoolAllocationRequest(allocator.pool, "org1", "game")
    allocator.allocate(request, credentials(request))
    other = PoolAllocationRequest(allocator.pool, "org2", "other")
    allocator.allocate(other, credentials(other))
    ca = tmp_path / "ca.pem"
    ca.write_text("Local SQL test only; AWS/TLS clients are replaced")
    config = {
        "version": 1,
        "settings": {
            "pool": asdict(allocator.pool),
            "resource_id": "db-TEST",
            "vpc_id": "vpc-11111111",
            "database_security_group": "sg-11111111",
            "allowed_client_groups": ["sg-22222222"],
            "admin_secret_arn": "arn:aws:secretsmanager:ap-northeast-2:111111111111:secret:admin-test01",
            "app_secret_kms_arn": "arn:aws:kms:ap-northeast-2:111111111111:key/11111111-1111-1111-1111-111111111111",
            "sslrootcert": str(ca),
        },
    }
    path = tmp_path / "pool.json"
    path.write_text(json.dumps(config))
    for key, value in {
        "SKY_DATABASE_HOST": "state.example",
        "SKY_DATABASE_NAME": "sky_state",
        "SKY_DATABASE_SECRET_ARN": "arn:aws:secretsmanager:ap-northeast-2:111111111111:secret:state-test01",
        "SKY_AWS_REGION": "ap-northeast-2",
        "SKY_DATABASE_SSLROOTCERT": str(ca),
        "SKY_COGNITO_AUTH_JSON": json.dumps(
            {"version": 1, "issuer": ISSUER, "client_id": "client123", "required_scopes": ["sky/deploy"]}
        ),
        "SKY_MEMBERSHIPS_JSON": json.dumps(
            {
                "version": 1,
                "members": [
                    {
                        "issuer": ISSUER,
                        "subject": "admin-sub",
                        "user_id": "user1",
                        "organization_id": "org1",
                        "role": "admin",
                        "enabled": True,
                    }
                ],
            }
        ),
    }.items():
        monkeypatch.setenv(key, value)
    for key in ("SKY_ALB_TRUSTS_JSON", "SKY_PRIVATE_OPERATOR_JSON", "SKY_SHARED_DATABASE_POOL_JSON"):
        monkeypatch.delenv(key, raising=False)
    settings, _ = load_pool_configuration(path)
    aws = AwsSharedDatabaseAllocator(settings, session=Mock(), connect=Mock())
    records = Records()
    records.job["workload_database_binding"] = asdict(request.binding())
    SecurityHold(records).place(
        principal(role=Role.ADMIN),
        records.job["id"],
        incident_id="INC-1",
        reason="suspected_compromise",
        now="2026-10-24T00:00:00+00:00",
    )
    boundary = records.job["security_review_boundary"]["id"]
    connection = application(request.database_name, request.login_role, credentials(request).password)
    try:
        with (
            patch("interfaces.security_hold.RotatingDatabaseConnection", return_value=Mock()),
            patch("interfaces.security_hold.check_database_ready"),
            patch("interfaces.security_hold.PostgresDeploymentRecordStore", return_value=records),
            patch("interfaces.security_hold.AwsSharedDatabaseAllocator", return_value=aws),
            patch.object(aws, "_audit", return_value=("pool.example", 5432, "admin")),
            patch.object(aws, "_admin_credentials", return_value=("admin", "test-password")),
            patch.object(aws, "_allocator", return_value=allocator),
            patch.object(aws, "_connection", side_effect=lambda host, port, name, *auth: admin(name)),
        ):
            main(command(path, revision=records.revision, boundary=boundary))
            restricted = json.loads(capsys.readouterr().out)["database_restriction"]
            assert restricted["phase"] == "verified"
            with pytest.raises(psycopg.OperationalError):
                application(request.database_name, request.login_role, credentials(request).password)
            with application(other.database_name, other.login_role, credentials(other).password) as db:
                assert db.execute("SELECT 1").fetchone() == (1,)
            writes = records.save_calls
            args = command(path, "inspect-database", records.revision, boundary)
            args[args.index("--expected-operation-id") + 1] = restricted["operation_id"]
            main(args)
            inspected = json.loads(capsys.readouterr().out)["database_restriction"]
            assert inspected["observed_state"] == "restricted" and inspected["read_only"]
            assert inspected["state_changed"] is False and records.save_calls == writes
            main(arguments())
            assert json.loads(capsys.readouterr().out)["database_restriction"]["phase"] == "verified"
    finally:
        connection.close()


def test_timeout_override_still_cannot_exceed_role_connections_or_access_neighbor(database, record_property):
    import json
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor

    adapter, _admin, application = database
    busy = PoolAllocationRequest(adapter.pool, "trusted-team", "capacity-probe", 1)
    neighbor = PoolAllocationRequest(adapter.pool, "neighbor-team", "capacity-neighbor", 2)
    for request in (busy, neighbor):
        adapter.allocate(request, credentials(request))
    samples = []
    started = threading.Event()
    with application(busy.database_name, busy.login_role, credentials(busy).password) as occupied:
        occupied.execute("SET statement_timeout=0")

        def bounded_work():
            started.set()
            occupied.execute("SELECT pg_sleep(1), count(*) FROM generate_series(1,50000)")

        with ThreadPoolExecutor(max_workers=1) as threads:
            future = threads.submit(bounded_work)
            assert started.wait(5)
            with pytest.raises(psycopg.OperationalError):
                application(busy.database_name, busy.login_role, credentials(busy).password)
            for _ in range(10):
                begin = time.monotonic()
                with application(
                    neighbor.database_name, neighbor.login_role, credentials(neighbor).password
                ) as db:
                    assert db.execute("SELECT 1").fetchone() == (1,)
                samples.append(time.monotonic() - begin)
            future.result(timeout=5)
    with pytest.raises(psycopg.OperationalError):
        application(neighbor.database_name, busy.login_role, credentials(busy).password)
    record_property("neighbor_elapsed_samples_s", json.dumps(samples))
    record_property("timeout_default_overridden", True)
    record_property("physical_resource_isolation_claimed", False)
