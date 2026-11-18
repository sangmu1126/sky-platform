from unittest.mock import Mock

import pytest

from application.copy_guard import UncommittedCopyGuard


def test_only_uncommitted_chunks_reuse_authorization_and_normal_commit_call_is_fresh():
    clock = [0.0]
    check = Mock()
    guard = UncommittedCopyGuard(check, clock=lambda: clock[0])
    guard()
    for _ in range(100):
        guard.uncommitted_copy_checkpoint()
    assert check.call_count == 1
    clock[0] = 1
    guard.uncommitted_copy_checkpoint()
    assert check.call_count == 2
    guard()  # SQL adapters call this before COMMIT, even within the reuse window.
    assert check.call_count == 3


def test_revocation_before_commit_and_cancellation_do_not_reuse_a_previous_success():
    check = Mock()
    guard = UncommittedCopyGuard(check)
    guard()
    check.side_effect = PermissionError("membership revoked")
    with pytest.raises(PermissionError):
        guard()
    guard.halted.set()
    with pytest.raises(RuntimeError):
        guard.uncommitted_copy_checkpoint()
    assert check.call_count == 2


@pytest.mark.parametrize("age", [0, 2, True, float("nan")])
def test_reuse_window_cannot_be_unbounded(age):
    with pytest.raises(ValueError):
        UncommittedCopyGuard(lambda: None, max_age_seconds=age)
