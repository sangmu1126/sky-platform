"""Real child processes, no Docker credentials or external network."""

import sys
import time

import pytest

from adapters.build.process import bounded_command


def test_large_diagnostics_are_retained_only_up_to_64k():
    code, output = bounded_command([sys.executable, "-c", "print('x' * 100000)"], timeout=5)
    assert code == 0 and len(output) == 65536


def test_noisy_child_is_stopped_without_persisting_its_output():
    with pytest.raises(OSError, match="output limit"):
        bounded_command(
            [sys.executable, "-c", "import os\nwhile True: os.write(1, b'x'*65536)"],
            timeout=5,
            output_limit=131072,
        )


def test_child_that_retains_stdout_cannot_bypass_deadline():
    started = time.monotonic()
    with pytest.raises(OSError, match="time limit"):
        bounded_command([sys.executable, "-c", "import time; time.sleep(20)"], timeout=0.15)
    assert time.monotonic() - started < 5


def test_closed_output_does_not_bypass_wait_deadline():
    with pytest.raises(OSError, match="time limit"):
        bounded_command(
            [sys.executable, "-c", "import os,time; os.close(1); os.close(2); time.sleep(20)"], timeout=0.15
        )


def test_failed_command_does_not_raise_or_print_untrusted_diagnostic():
    assert bounded_command(
        [sys.executable, "-c", "print('synthetic-canary'); raise SystemExit(3)"], timeout=5
    ) == (3, "synthetic-canary\n")


@pytest.mark.parametrize("options", [{"timeout": True}, {"timeout": 3601}, {"output_limit": 0}])
def test_unbounded_configuration_is_rejected_before_start(options):
    with pytest.raises(ValueError):
        bounded_command([sys.executable], **options)
