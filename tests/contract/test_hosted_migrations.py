"""Execute uploaded SQL as a restricted role on a disposable PostgreSQL server."""

import time
from uuid import uuid4

import pytest

from adapters.database.hosted_migrations import apply_hosted_migrations
from tests.contract.test_build_consumer import database as database  # noqa: PLC0414

psycopg = pytest.importorskip("psycopg")
from psycopg import sql


@pytest.fixture
def workload(database, tmp_path):
    nonce = uuid4().hex[:12]
    role, name, password = "migration_" + nonce, "migration_" + nonce, "synthetic-test-" + nonce
    with database() as db:
        db.autocommit = True
        db.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 3"
            ).format(sql.Identifier(role), sql.Literal(password))
        )
        db.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(name), sql.Identifier(role)))
        parameters = {**db.info.get_parameters(), "dbname": name, "user": role, "password": password}
    directory = tmp_path / "migrations"
    directory.mkdir()
    path = directory / "0001_data.sql"
    path.write_text(
        "CREATE TABLE rows(id integer primary key, value text); INSERT INTO rows VALUES (1, 'synthetic');"
    )
    try:
        yield tmp_path, lambda: psycopg.connect(**parameters)
    finally:
        with database() as db:
            db.autocommit = True
            db.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name)))
            db.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


def test_atomic_apply_replay_and_changed_ledger_rejected(workload):
    project, connect = workload
    report = apply_hosted_migrations(project, connect, guard=lambda: None)
    assert report["migrations"] == 1 and report["replayed"] == 0
    assert apply_hosted_migrations(project, connect, guard=lambda: None)["replayed"] == 1
    (project / "migrations" / "0001_data.sql").write_text("SELECT 1;")
    with pytest.raises(ValueError, match="changed"):
        apply_hosted_migrations(project, connect, guard=lambda: None)
    with connect() as db:
        assert db.execute("SELECT * FROM rows").fetchall() == [(1, "synthetic")]


@pytest.mark.parametrize(
    "statement", ["CREATE ROLE forbidden SUPERUSER;", "CREATE DATABASE forbidden;", "SET ROLE postgres;"]
)
def test_uploaded_sql_cannot_escalate(workload, statement):
    project, connect = workload
    (project / "migrations" / "0001_data.sql").write_text(statement)
    with pytest.raises(psycopg.Error):
        apply_hosted_migrations(project, connect, guard=lambda: None)
    with connect() as db:
        assert db.execute("SELECT to_regclass('sky_schema_migrations')").fetchone() == (None,)


def test_sql_cannot_disable_external_deadline(workload):
    project, connect = workload
    (project / "migrations" / "0001_data.sql").write_text("SET statement_timeout=0; SELECT pg_sleep(15);")
    start = time.monotonic()
    with pytest.raises((psycopg.errors.QueryCanceled, TimeoutError)):
        apply_hosted_migrations(project, connect, guard=lambda: None, timeout_seconds=1)
    assert time.monotonic() - start < 5
    with connect() as db:
        assert db.execute("SELECT to_regclass('sky_schema_migrations')").fetchone() == (None,)


def test_revocation_before_commit_rolls_back_schema_and_rows(workload):
    project, connect = workload
    calls = []

    def guard():
        calls.append(True)
        if len(calls) == 3:
            raise PermissionError("synthetic approval revoked")

    with pytest.raises(PermissionError):
        apply_hosted_migrations(project, connect, guard=guard)
    with connect() as db:
        assert db.execute("SELECT to_regclass('rows'),to_regclass('sky_schema_migrations')").fetchone() == (
            None,
            None,
        )
