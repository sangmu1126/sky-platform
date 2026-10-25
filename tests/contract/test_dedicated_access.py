import pytest

from adapters.database.dedicated_access import PostgresDedicatedAccess, access_identity
from domain.database import DatabaseBinding
from tests.contract.test_promotion_copy import databases as databases  # noqa: PLC0414
from tests.contract.test_promotion_copy import psycopg, seed


@pytest.fixture
def access(databases):
    (_source, target), plan = databases
    from psycopg import sql

    # Local fixture emulates two instances in one cluster: the source DB must
    # not expose default PUBLIC CONNECT to the new dedicated login.
    with _source() as db:
        db.execute(
            sql.SQL("REVOKE CONNECT ON DATABASE {} FROM PUBLIC").format(
                sql.Identifier(plan["source"]["database_name"])
            )
        )
    seed(target)
    binding = DatabaseBinding(**plan["target"])
    role, _ = access_identity(binding)

    def login(user, password):
        with target() as db:
            params = db.info.get_parameters()
        return psycopg.connect(**{**params, "user": user, "password": password})

    adapter = PostgresDedicatedAccess(target, login)
    yield adapter, binding, target, login
    from psycopg import sql

    with target() as db:
        if db.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,)).fetchone():
            db.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            db.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


def prepare(adapter, binding, guard=lambda: None):
    return adapter.provision(
        binding, password="disposable-app-password", secret_ref="test-secret-reference", guard=guard
    )


def test_app_has_crud_without_schema_or_database_admin_rights(access):
    adapter, binding, _admin, login = access
    receipt = prepare(adapter, binding)
    with login(receipt["login_role"], "disposable-app-password") as db:
        assert db.execute("SELECT count(*) FROM scores").fetchone() == (2,)
        db.execute("INSERT INTO scores VALUES(3,10,'app',NULL)")
        db.execute("UPDATE scores SET score=11 WHERE id=3")
        db.execute("DELETE FROM scores WHERE id=3")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            db.execute("CREATE TABLE forbidden(id integer)")
    assert receipt["routing_changed"] is False
    assert "disposable-app-password" not in str(receipt)


def test_owned_retry_uses_same_role_and_secret(access):
    adapter, binding, _, _ = access
    assert prepare(adapter, binding) == prepare(adapter, binding)


def test_foreign_role_not_adopted(access):
    adapter, binding, admin, _ = access
    from psycopg import sql

    role, _ = access_identity(binding)
    with admin() as db:
        db.execute(sql.SQL("CREATE ROLE {}").format(sql.Identifier(role)))
    with pytest.raises(ValueError, match="unowned"):
        prepare(adapter, binding)


def test_lost_guard_rolls_back_new_role(access):
    adapter, binding, admin, _ = access
    calls = 0

    def guard():
        nonlocal calls
        calls += 1
        if calls == 3:
            raise RuntimeError("lease lost")

    with pytest.raises(RuntimeError):
        prepare(adapter, binding, guard)
    role, _ = access_identity(binding)
    with admin() as db:
        assert db.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,)).fetchone() is None


def test_existing_role_privilege_escalation_is_rejected(access):
    adapter, binding, admin, _ = access
    receipt = prepare(adapter, binding)
    from psycopg import sql

    with admin() as db:
        db.execute(sql.SQL("ALTER ROLE {} CREATEDB").format(sql.Identifier(receipt["login_role"])))
    with pytest.raises(ValueError, match="privileges"):
        prepare(adapter, binding)


def test_unrelated_database_public_connect_is_rejected_without_publishing_app_role(access):
    import os
    from uuid import uuid4

    from psycopg import sql

    adapter, binding, admin, _ = access
    role, _ = access_identity(binding)
    unrelated = "unrelated_" + uuid4().hex[:12]
    with psycopg.connect(os.environ["SKY_TEST_PROMOTION_POSTGRES_DSN"], autocommit=True) as root:
        root.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(unrelated)))
        try:
            with pytest.raises(ValueError, match="Application role can connect to another database"):
                prepare(adapter, binding)
            with admin() as db:
                assert db.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,)).fetchone() is None
        finally:
            root.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(unrelated)))


def test_existing_dedicated_access_is_read_only_and_accepts_nologin(access):
    from unittest.mock import patch

    from psycopg import sql

    from adapters.database.promotion_fence import PostgresApplicationFence

    adapter, binding, admin, _login = access
    receipt = prepare(adapter, binding)
    with admin() as db:
        db.execute(sql.SQL("ALTER ROLE {} NOLOGIN").format(sql.Identifier(receipt["login_role"])))
    original = PostgresApplicationFence._verify_ownership

    def read_only(fence, db):
        assert db.execute("SHOW transaction_read_only").fetchone() == ("on",)
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction), db.transaction():
            db.execute("UPDATE public.scores SET score=score WHERE false")
        original(fence, db)

    with patch.object(PostgresApplicationFence, "_verify_ownership", new=read_only):
        result = adapter.existing_access(binding, connection_limit=5, guard=lambda: None)
    assert result["login_role"] == receipt["login_role"]
    with admin() as db:
        assert db.execute(
            "SELECT rolcanlogin FROM pg_roles WHERE rolname=%s", (receipt["login_role"],)
        ).fetchone() == (False,)


@pytest.mark.parametrize("change", ["limit", "inherit", "marker", "control-schema"])
def test_existing_dedicated_registration_drift_is_rejected_without_restoring_login(access, change):
    from psycopg import sql

    adapter, binding, admin, _login = access
    receipt = prepare(adapter, binding)
    with admin() as db:
        db.execute(sql.SQL("ALTER ROLE {} NOLOGIN").format(sql.Identifier(receipt["login_role"])))
        if change == "inherit":
            db.execute(sql.SQL("ALTER ROLE {} INHERIT").format(sql.Identifier(receipt["login_role"])))
        elif change == "marker":
            db.execute(
                sql.SQL("COMMENT ON DATABASE {} IS 'foreign'").format(sql.Identifier(binding.database_name))
            )
        elif change == "control-schema":
            db.execute("CREATE SCHEMA sky_state")
    with pytest.raises(ValueError):
        adapter.existing_access(binding, connection_limit=6 if change == "limit" else 5, guard=lambda: None)
    with admin() as db:
        assert db.execute(
            "SELECT rolcanlogin FROM pg_roles WHERE rolname=%s", (receipt["login_role"],)
        ).fetchone() == (False,)


def test_dedicated_fence_restricts_existing_session_and_inspects_without_data_changes(access):
    from adapters.database.incident_restriction import PostgresIncidentRestriction
    from adapters.database.promotion_fence import PostgresApplicationFence

    adapter, binding, admin, login = access
    prepare(adapter, binding)
    role, marker = access_identity(binding)
    held = login(role, "disposable-app-password")
    try:
        held.execute("SELECT count(*) FROM scores")
        adapter.existing_access(binding, connection_limit=5, guard=lambda: None)
        restriction = PostgresIncidentRestriction(PostgresApplicationFence(admin, binding, role, marker))
        assert restriction.restrict(guard=lambda: None)["login_enabled"] is False
        with pytest.raises(psycopg.OperationalError):
            held.execute("SELECT 1")
        with pytest.raises(psycopg.OperationalError):
            login(role, "disposable-app-password")
        adapter.existing_access(binding, connection_limit=5, guard=lambda: None)
        report = restriction.inspect(guard=lambda: None)
        assert report["read_only"] and report["login_enabled"] is False and report["active_sessions"] == 0
        with admin() as db:
            assert db.execute("SELECT count(*) FROM scores").fetchone() == (2,)
    finally:
        held.close()
