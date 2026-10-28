"""Real pooled readers and writers across planned-migration ACL fences."""

from uuid import uuid4

import psycopg
import pytest
from psycopg import sql

from adapters.database.promotion_write_fence import PostgresPromotionWriteFence
from domain.database import DatabaseBinding
from tests.contract.test_promotion_copy import databases as databases  # noqa: PLC0414
from tests.contract.test_promotion_copy import seed


@pytest.fixture
def registered(databases):
    (connect, _), plan = databases
    seed(connect)
    role = "sky_login_" + uuid4().hex[:24]
    marker = "sky-pool-allocation-v1:" + role.removeprefix("sky_login_")
    with connect() as db:
        db.execute(sql.SQL("CREATE ROLE {} LOGIN NOINHERIT").format(sql.Identifier(role)))
        db.execute(sql.SQL("COMMENT ON ROLE {} IS {}").format(sql.Identifier(role), sql.Literal(marker)))
        db.execute(
            sql.SQL("COMMENT ON DATABASE {} IS {}").format(
                sql.Identifier(plan["source"]["database_name"]), sql.Literal(marker)
            )
        )
        db.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        db.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(role)))
        db.execute(sql.SQL("GRANT SELECT,INSERT,UPDATE,DELETE ON scores TO {}").format(sql.Identifier(role)))
    fence = PostgresPromotionWriteFence(connect, DatabaseBinding(**plan["source"]), role, marker)
    try:
        yield connect, role, fence
    finally:
        with connect() as db:
            db.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            db.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


def pooled(connect, role):
    db = connect()
    db.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(role)))
    db.commit()
    return db


def test_existing_reader_survives_write_fence_and_exact_dml_restoration(registered):
    connect, role, fence = registered
    with pooled(connect, role) as reader:
        assert reader.execute("SELECT count(*) FROM scores").fetchone() == (2,)
        reader.commit()
        fence.set_writes(False, guard=lambda: None)
        assert reader.execute("SELECT count(*) FROM scores").fetchone() == (2,)
        reader.commit()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            reader.execute("INSERT INTO scores VALUES(3,1,NULL,NULL)")
        reader.rollback()
        fence.set_writes(True, guard=lambda: None)
        reader.execute("INSERT INTO scores VALUES(3,1,NULL,NULL)")
        reader.commit()
        assert reader.execute("SELECT count(*) FROM scores").fetchone() == (3,)
        reader.commit()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            reader.execute("TRUNCATE scores")
        reader.rollback()


@pytest.mark.parametrize("privilege", ["CREATE ON SCHEMA public", "UPDATE(score) ON scores"])
def test_unsupported_schema_or_column_privileges_rejected_before_change(registered, privilege):
    connect, role, fence = registered
    with connect() as db:
        db.execute(sql.SQL("GRANT {} TO {}").format(sql.SQL(privilege), sql.Identifier(role)))
    with pytest.raises(ValueError):
        fence.set_writes(False, guard=lambda: None)
    with pooled(connect, role) as db:
        db.execute("INSERT INTO scores VALUES(3,1,NULL,NULL)")


def test_lease_loss_rolls_back_revoke_and_keeps_readers(registered):
    connect, role, fence = registered
    calls = 0

    def guard():
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("lease lost")

    with pytest.raises(RuntimeError, match="lease lost"):
        fence.set_writes(False, guard=guard)
    with pooled(connect, role) as db:
        db.execute("INSERT INTO scores VALUES(3,1,NULL,NULL)")
        assert db.execute("SELECT count(*) FROM scores").fetchone() == (3,)


def test_fence_drains_existing_writer_without_killing_pooled_reader(registered):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    connect, role, fence = registered
    entered = threading.Event()
    with pooled(connect, role) as writer, pooled(connect, role) as reader:
        writer.execute("UPDATE scores SET score=99 WHERE id=1")
        writer_pid = writer.execute("SELECT pg_backend_pid()").fetchone()[0]

        def freeze():
            entered.set()
            return fence.set_writes(False, guard=lambda: None)

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(freeze)
            assert entered.wait(2)
            # Reader observes the old committed row while a writer is draining.
            reader.execute("SET LOCAL statement_timeout='500ms'")
            assert reader.execute("SELECT score FROM scores WHERE id=1").fetchone() == (42,)
            reader.commit()
            writer.commit()
            assert future.result(timeout=10)["reads_preserved"]
        assert writer.execute("SELECT pg_backend_pid()").fetchone() == (writer_pid,)
        assert reader.execute("SELECT score FROM scores WHERE id=1").fetchone() == (99,)
        reader.commit()
        writer.commit()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            writer.execute("UPDATE scores SET score=100 WHERE id=1")
        writer.rollback()


def test_prepared_write_cannot_bypass_committed_fence(registered):
    connect, role, fence = registered
    with pooled(connect, role) as db:
        db.execute("PREPARE old_write AS UPDATE scores SET score=99 WHERE id=1")
        db.commit()
        fence.set_writes(False, guard=lambda: None)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            db.execute("EXECUTE old_write")
        db.rollback()
        assert db.execute("SELECT score FROM scores WHERE id=1").fetchone() == (42,)


def test_writer_queued_behind_fence_cannot_execute_after_revoke(registered):
    import time
    from concurrent.futures import ThreadPoolExecutor

    connect, role, fence = registered
    with pooled(connect, role) as writer, ThreadPoolExecutor(max_workers=1) as executor:
        pid = writer.execute("SELECT pg_backend_pid()").fetchone()[0]
        writer.commit()
        pending = []
        calls = 0

        def write():
            try:
                writer.execute("UPDATE scores SET score=777 WHERE id=1")
                writer.commit()
                return "wrote"
            except psycopg.errors.InsufficientPrivilege:
                writer.rollback()
                return "denied"

        def guard():
            nonlocal calls
            calls += 1
            if calls == 2:
                pending.append(executor.submit(write))
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    with connect() as observer:
                        if observer.execute(
                            "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=%s AND NOT granted)", (pid,)
                        ).fetchone()[0]:
                            return
                    time.sleep(0.01)
                raise AssertionError("Writer did not queue behind the write fence")

        fence.set_writes(False, guard=guard)
        assert pending[0].result(timeout=5) == "denied"
        with connect() as db:
            assert db.execute("SELECT score FROM scores WHERE id=1").fetchone() == (42,)
