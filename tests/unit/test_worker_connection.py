from contextlib import contextmanager
from unittest.mock import Mock

import pytest

from adapters.state.worker_connection import ScopedWorkerConnection


def setup():
    db = Mock(autocommit=False, closed=False)
    events = []

    @contextmanager
    def transaction():
        events.append("begin")
        try:
            yield
        except BaseException:
            events.append("rollback")
            raise
        else:
            events.append("commit")

    db.transaction.side_effect = transaction
    connect = Mock(return_value=db)
    return ScopedWorkerConnection(connect), db, connect, events


def test_reuse_keeps_separate_commits_and_closes_only_at_worker_scope_end():
    scope, db, connect, events = setup()
    with scope as factory:
        for _ in range(3):
            with factory() as borrowed:
                assert borrowed is db
        db.close.assert_not_called()
    connect.assert_called_once()
    db.close.assert_called_once()
    assert events == ["begin", "commit"] * 3
    with pytest.raises(OSError, match="reconcile"), factory():
        pass


def test_statement_or_commit_outcome_is_never_automatically_retried():
    scope, db, connect, events = setup()
    with scope as factory:
        with pytest.raises(OSError, match="unknown commit"), factory():
            raise OSError("unknown commit")
        assert events == ["begin", "rollback"]
        connect.assert_called_once()
        db.closed = True
        with pytest.raises(OSError, match="reconcile"), factory():
            pass
        assert events == ["begin", "rollback"]


def test_nested_use_and_autocommit_are_not_silently_adopted():
    scope, _, _, events = setup()
    with scope as factory:
        with pytest.raises(RuntimeError, match="Nested"), factory(), factory():
            pass
        assert events == ["begin", "rollback"]
    scope, db, _, _ = setup()
    db.autocommit = True
    with pytest.raises(ValueError, match="Transactional"), scope:
        pass
    db.close.assert_called_once()
