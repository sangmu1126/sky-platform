"""Opt-in real Chrome against a synthetic authenticated loopback preparation API.

This tests DOM/network/storage and HTTP composition, not ALB, SQL durability or RDS.
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest

from tests.unit.test_operating_review import ID

pytest_plugins = ["tests.unit.test_database_preparation_http"]


def test_real_browser_approval_ambiguous_admission_and_reload(web):
    request, _controller, records, operations, _body, operation = web
    records.job["operating_proposal"]["status"] = "pending_approval"
    records.job["operating_proposal"].pop("approval")
    saved = []
    polls = []

    def admit(_app, _kind, _key, command):
        if saved:
            assert saved[0].command == command
            return saved[0]
        saved.append(replace(operation, command=command))
        return saved[0]

    def get(_identity):
        assert saved and _identity == operation.id
        polls.append(True)
        return replace(saved[0], status="succeeded" if len(polls) >= 4 else "queued")

    operations.admit.side_effect, operations.get.side_effect = admit, get
    report = run_browser(request.origin, operation.id)
    assert report["status"] == "passed"
    assert len(saved) == 1 and operations.admit.call_count == 2 and len(polls) >= 4


def run_browser(origin, operation_id, *, terminal="succeeded"):
    """Reusable real renderer; callers choose synthetic or SQL-backed API state."""
    binary = os.environ.get("SKY_TEST_BROWSER_CHROME")
    if not binary:
        pytest.skip("Explicit disposable Chrome executable required")
    chrome_path = Path(binary)
    assert chrome_path.is_file(), "Configured Chrome executable must exist"
    assert shutil.which("node"), "Node 22+ required for native CDP WebSocket"
    driver = Path(__file__).resolve().parents[1] / "live/browser_database_preparation_cdp.mjs"
    output = os.environ.get("SKY_TEST_BROWSER_OUTPUT_DIR")
    with (
        patch("boto3.client", side_effect=AssertionError("Cloud clients forbidden in browser fixture")),
        TemporaryDirectory(prefix="sky-preparation-browser-") as directory,
    ):
        root = Path(directory)
        profile = root / "profile"
        with (root / "chrome.log").open("w+") as log:
            flags = [
                str(chrome_path),
                "--headless=new",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-background-networking",
                "--disable-gpu",
                "--no-proxy-server",
                "--remote-debugging-address=127.0.0.1",
                "--remote-debugging-port=0",
                "--user-data-dir=" + str(profile),
                "about:blank",
            ]
            if sys.platform.startswith("linux"):
                # Disposable CI renderer only: trusted fixture, no user code or credentials.
                flags.insert(1, "--no-sandbox")
            chrome = subprocess.Popen(flags, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                deadline = time.monotonic() + 30
                port_file = profile / "DevToolsActivePort"
                while not port_file.is_file():
                    if chrome.poll() is not None or time.monotonic() >= deadline:
                        raise AssertionError("Disposable Chrome debugging endpoint unavailable")
                    time.sleep(0.1)
                result = subprocess.run(
                    [
                        "node",
                        str(driver),
                        origin,
                        port_file.read_text().splitlines()[0],
                        ID,
                        operation_id,
                        output or "",
                        terminal,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=100,
                )
                assert result.returncode == 0, result.stdout + result.stderr
                report = json.loads(result.stdout.strip())
                assert report["status"] == "passed" and report["same_request_key"] is True
            finally:
                # Chrome can leave profile-writing children after its parent exits.
                # This group belongs only to our start_new_session test process.
                try:
                    os.killpg(chrome.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    chrome.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(chrome.pid, signal.SIGKILL)
                    chrome.wait(timeout=10)
                finally:
                    try:
                        os.killpg(chrome.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                # Wait for killed writers to stop before TemporaryDirectory runs
                # its strict cleanup; never suppress a final cleanup failure.
                deadline = time.monotonic() + 3
                while True:
                    try:
                        shutil.rmtree(profile)
                        break
                    except FileNotFoundError:
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.1)
    return report
