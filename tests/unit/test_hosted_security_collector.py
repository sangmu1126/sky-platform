"""Hosted observer works from the installed package, with no source checkout or key files."""

import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

from interfaces.security_collector import collect_cycle, document, hosted_main


def test_installed_collector_import_does_not_depend_on_repository_scripts(tmp_path):
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import interfaces.security_collector,sys; assert not any(x=='scripts' or x.startswith('scripts.') for x in sys.modules)",
        ],
        check=False,
        cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(root / "src")},
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr


def test_duplicate_registration_refused():
    with pytest.raises(ValueError, match="Duplicate"):
        document('{"version":1,"version":1}')


def test_expired_collection_stops_before_any_aws_client():
    session = Mock()
    now = datetime.now(UTC)
    config = {
        "version": 1,
        "expires_at": (now - timedelta(seconds=1)).isoformat(),
        "aws": {},
        "detector": {},
        "scope": {},
        "audit": {},
    }
    with pytest.raises(ValueError, match="expired"):
        collect_cycle(config, Mock(), Path("/unused"), session=session, now=now.isoformat())
    session.client.assert_not_called()


def test_missing_task_identity_fails_closed_without_key_diagnostics(monkeypatch, capsys):
    monkeypatch.delenv("ECS_CONTAINER_METADATA_URI_V4", raising=False)
    monkeypatch.setenv("SKY_SECURITY_SIGNING_PRIVATE_KEY", "synthetic-never-log")
    with pytest.raises(SystemExit):
        hosted_main()
    captured = capsys.readouterr()
    assert "collection_incomplete" in captured.out
    assert "synthetic-never-log" not in captured.out + captured.err
