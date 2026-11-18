"""Actual PostgreSQL transaction reuse and durable operation journal checks."""

from unittest.mock import Mock
from uuid import uuid4

import pytest

psycopg = pytest.importorskip("psycopg")
from adapters.state.operations import PostgresOperationStore
from adapters.state.worker_connection import ScopedWorkerConnection
from application.database_cutover import OperationCutoverJournal
from tests.contract.test_database_migration_reviews import database as database  # noqa: PLC0414 -- pytest fixture re-export


def test_reused_real_connection_preserves_commit_and_rolls_back_only_failed_transaction(database):
    connect = Mock(side_effect=database)
    with ScopedWorkerConnection(connect) as borrowed:
        with borrowed() as db:
            identity = db.info.backend_pid
            db.execute("CREATE TEMP TABLE reuse_check(id integer PRIMARY KEY) ON COMMIT PRESERVE ROWS")
            db.execute("INSERT INTO reuse_check VALUES(1)")
        with pytest.raises(psycopg.errors.UniqueViolation), borrowed() as db:
            db.execute("INSERT INTO reuse_check VALUES(2)")
            db.execute("INSERT INTO reuse_check VALUES(1)")
        with borrowed() as db:
            assert db.info.backend_pid == identity
            assert db.execute("SELECT id FROM reuse_check ORDER BY id").fetchall() == [(1,)]
    connect.assert_called_once()
    assert db.closed


def test_closed_connection_does_not_retry_or_reopen_the_previous_statement(database):
    connect = Mock(side_effect=database)
    with ScopedWorkerConnection(connect) as borrowed:
        with borrowed() as db:
            db.execute("SELECT 1")
        db.close()
        with pytest.raises(OSError, match="reconcile"), borrowed():
            pass
    connect.assert_called_once()


def test_operation_journal_persists_new_environment_kind_across_worker_connection_scope(database):
    workspace = uuid4().hex
    with ScopedWorkerConnection(database) as borrowed:
        store = PostgresOperationStore(borrowed, workspace=workspace)
        operation = store.admit(
            "app", "environment_transfer", "request", {"organization_id": "org", "created_by": "alice"}
        )
        lease = store.claim(operation.id, operation.attempt_id, "worker", seconds=90)
        journal = OperationCutoverJournal(store, lease, effect_kind="environment_transfer")
        journal.begin({"plan_id": "test-registration"})
        assert store.get(operation.id).external_intent["kind"] == "environment_transfer"
        journal({"stage": "qualified_test", "status": "observed"})
        journal.finish({"verified_scope": "test_no_external_effect"})
    fresh = PostgresOperationStore(database, workspace=workspace)
    saved = fresh.get(operation.id)
    assert saved.status == "succeeded" and not saved.external_pending
    assert saved.checkpoint["cutover_steps"] == [{"stage": "qualified_test", "status": "observed"}]
