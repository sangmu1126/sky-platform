"""Reproduce partial Chrome port-file writes without launching a browser."""

from unittest.mock import Mock, patch

import pytest

from tests.unit.test_database_preparation_browser import wait_for_debug_port


def test_partial_or_absent_file_is_not_ready():
    path = Mock()
    path.read_text.side_effect = [
        FileNotFoundError(),
        "",
        "9222",
        "invalid\n/devtools/browser/id",
        "9222\n/devtools/browser/id\n",
    ]
    process = Mock()
    process.poll.return_value = None
    with patch("time.sleep") as sleep:
        assert wait_for_debug_port(path, process) == "9222"
    assert sleep.call_count == 4


def test_process_exit_does_not_reuse_a_stale_port_file():
    path = Mock()
    process = Mock()
    process.poll.return_value = 1
    with pytest.raises(AssertionError):
        wait_for_debug_port(path, process)
    path.read_text.assert_not_called()


def test_partial_file_has_bounded_wait():
    path = Mock()
    path.read_text.return_value = ""
    process = Mock()
    process.poll.return_value = None
    with pytest.raises(AssertionError):
        wait_for_debug_port(path, process, timeout=0)
