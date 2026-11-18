"""Actual TLS PostgreSQL copy/fence/refresh/recovery with explicit AWS port double.

Both SQL servers are disposable VM containers. The source AWS ownership verifier
is a labelled double: these tests are transport proof, not AWS migration E2E.
"""

import hashlib
import os
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock
from uuid import uuid4

import pytest

psycopg = pytest.importorskip("psycopg")
from psycopg import sql

from adapters.database.environment_fence import PostgresEnvironmentWriteFence
from adapters.database.environment_transfer import PostgresEnvironmentTransfer, RegisteredTransferEndpoint
from adapters.database.migration_inventory import PostgresInventoryRegistration
from domain.database_inventory import DatabaseResourceEvidence
from domain.database_migration import DatabaseLocation, MigrationSafetyPolicy
from domain.database_transfer import RegisteredDatabaseTransfer
from tests.contract.test_migration_inventory import databases as databases  # noqa: PLC0414 -- pytest fixture re-export


@pytest.fixture
def transport(databases):
    placements, readers, connects = databases
    source = replace(
        placements[0], location=DatabaseLocation("aws", "rds_postgresql", "111111111111", "ap-northeast-2")
    )
    target = placements[1]
    plan = RegisteredDatabaseTransfer(
        "sql-contract-registration", source, target, "a" * 64, MigrationSafetyPolicy(120, 600, 86400)
    )
    params = [
        psycopg.conninfo.conninfo_to_dict(os.environ[key])
        for key in (
            "SKY_TEST_MIGRATION_SOURCE_DSN",
            "SKY_TEST_MIGRATION_TARGET_DSN",
        )
    ]
    endpoints = tuple(
        RegisteredTransferEndpoint(
            PostgresInventoryRegistration(
                placement,
                value["host"],
                int(value["port"]),
                value["user"],
                value["sslrootcert"],
                hashlib.sha256(Path(value["sslrootcert"]).read_bytes()).hexdigest(),
            ),
            int(value["port"]),
        )
        for placement, value in zip((source, target), params)
    )
    source_verifier = Mock(
        verify=Mock(
            side_effect=lambda placement: DatabaseResourceEvidence(
                placement,
                "explicit-aws-port-double",
                datetime.now(UTC),
                params[0]["host"],
                int(params[0]["port"]),
            )
        )
    )
    transfer = PostgresEnvironmentTransfer(
        plan, *endpoints, *connects, source_verifier, readers[1].resource_verifier
    )
    return plan, transfer, connects, params


def test_actual_copy_final_refresh_and_reverse_preserve_new_commits(transport):
    plan, transfer, connects, _ = transport
    initial = transfer.copy(plan, guard=lambda: None)
    assert initial["source"]["location"]["provider"] == "aws"
    assert initial["target"]["location"]["provider"] == "onprem"
    with connects[0]() as db:
        db.execute("UPDATE scores SET score=43 WHERE id=1")
        db.execute("DELETE FROM scores WHERE id=2")
        db.execute("INSERT INTO scores VALUES(3,126)")
    final = transfer.refresh(plan, expected_destination=initial, guard=lambda: None)
    with connects[1]() as db:
        assert db.execute("SELECT * FROM scores ORDER BY id").fetchall() == [(1, 43), (3, 126)]
        db.execute("INSERT INTO scores VALUES(4,168)")
    recovered = transfer.refresh(plan, expected_destination=final, guard=lambda: None, reverse=True)
    assert recovered["verified_scope"] == "reverse_recovery_copy"
    with connects[0]() as db:
        assert db.execute("SELECT * FROM scores ORDER BY id").fetchall() == [(1, 43), (3, 126), (4, 168)]


def test_actual_changed_destination_cannot_be_overwritten(transport):
    plan, transfer, connects, _ = transport
    baseline = transfer.copy(plan, guard=lambda: None)
    with connects[1]() as db:
        db.execute("INSERT INTO scores VALUES(99,999)")
    with pytest.raises(ValueError, match="Destination changed"):
        transfer.refresh(plan, expected_destination=baseline, guard=lambda: None)
    with connects[1]() as db:
        assert db.execute("SELECT * FROM scores WHERE id=99").fetchone() == (99, 999)


@pytest.mark.parametrize("refresh", [False, True])
def test_revocation_after_copy_chunks_rolls_back_instead_of_committing(transport, refresh):
    from application.copy_guard import UncommittedCopyGuard

    plan, adapter, connects, _ = transport
    baseline = None
    if refresh:
        baseline = adapter.copy(plan, guard=lambda: None)
        with connects[0]() as db:
            db.execute("INSERT INTO scores VALUES(3,126)")
    revoked = [False]

    def check():
        if revoked[0]:
            raise PermissionError("Revoked before commit")

    core = UncommittedCopyGuard(check, clock=lambda: 0.0)

    class Guard:
        def __call__(self):
            core()

        def uncommitted_copy_checkpoint(self):
            core.uncommitted_copy_checkpoint()
            revoked[0] = True

    with pytest.raises(PermissionError, match="before commit"):
        if refresh:
            adapter.refresh(plan, expected_destination=baseline, guard=Guard())
        else:
            adapter.copy(plan, guard=Guard())
    with connects[1]() as db:
        if refresh:
            assert db.execute("SELECT id,score FROM scores ORDER BY id").fetchall() == [(1, 42), (2, 84)]
        else:
            assert db.execute("SELECT to_regclass('public.scores')").fetchone() == (None,)


def test_actual_nonempty_target_is_not_adopted_or_overwritten(transport):
    plan, transfer, connects, _ = transport
    with connects[1]() as db:
        db.execute("CREATE TABLE scores(id integer PRIMARY KEY, score bigint NOT NULL)")
        db.execute("INSERT INTO scores VALUES(99,999)")
    with pytest.raises(ValueError, match="Target must be empty"):
        transfer.copy(plan, guard=lambda: None)
    with connects[1]() as db:
        assert db.execute("SELECT * FROM scores").fetchall() == [(99, 999)]


def test_actual_write_fence_preserves_reads_and_only_restores_qualified_dml(transport):
    plan, transfer, connects, params = transport
    transfer.copy(plan, guard=lambda: None)
    index = uuid4().hex[:16]
    role, marker = "sky_transfer_" + index, "sky-transfer-v1:" + hashlib.sha256(index.encode()).hexdigest()
    password = uuid4().hex
    with connects[0]() as db:
        db.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS"
            ).format(sql.Identifier(role), sql.Literal(password))
        )
        db.execute(sql.SQL("COMMENT ON ROLE {} IS {}").format(sql.Identifier(role), sql.Literal(marker)))
        db.execute(
            sql.SQL("COMMENT ON DATABASE {} IS {}").format(
                sql.Identifier(plan.source.database_name), sql.Literal(marker)
            )
        )
        db.execute(
            sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(plan.source.database_name))
        )
        db.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
        db.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                sql.Identifier(plan.source.database_name), sql.Identifier(role)
            )
        )
        db.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(role)))
        db.execute(sql.SQL("GRANT SELECT,INSERT,UPDATE,DELETE ON scores TO {}").format(sql.Identifier(role)))
    fence = PostgresEnvironmentWriteFence(transfer, "source", role, marker)
    app = lambda: psycopg.connect(**{**params[0], "user": role, "password": password})
    try:
        assert fence.set_writes(False, guard=lambda: None)["reads_preserved"] is True
        with app() as db:
            assert db.execute("SELECT count(*) FROM scores").fetchone() == (2,)
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                db.execute("INSERT INTO scores VALUES(3,126)")
        assert fence.set_writes(True, guard=lambda: None)["writes_enabled"] is True
        with app() as db:
            db.execute("INSERT INTO scores VALUES(3,126)")
        with app() as db, pytest.raises(psycopg.errors.InsufficientPrivilege):
            db.execute("TRUNCATE scores")
    finally:
        with connects[0]() as db:
            db.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            db.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
            db.execute(
                sql.SQL("COMMENT ON DATABASE {} IS NULL").format(sql.Identifier(plan.source.database_name))
            )
