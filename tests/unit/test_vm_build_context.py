"""Preparing a VM context never executes source or transfers host credentials."""

import tarfile
from unittest.mock import Mock, patch

import pytest

from adapters.build.vm_builder import pack_context
from scripts.remote_builder import build


def test_context_drops_credentials_and_preserves_regular_source(tmp_path):
    root = tmp_path / "context"
    root.mkdir()
    (root / "Dockerfile").write_text("FROM scratch\n")
    (root / ".env").write_text("PRIVATE_KEY=synthetic-canary")
    (root / ".git").mkdir()
    (root / ".git/config").write_text("synthetic-private")
    (root / "index.html").write_text("normal source")
    path = tmp_path / "context.tar"
    pack_context(root, path)
    with tarfile.open(path) as archive:
        assert archive.getnames() == ["Dockerfile", "index.html"]
    assert b"synthetic-canary" not in path.read_bytes()


def test_context_link_refused_before_any_vm_or_read_of_outside_file(tmp_path):
    root = tmp_path / "context"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("synthetic-canary")
    (root / "app.py").symlink_to(outside)
    with pytest.raises(ValueError, match="symbolic"):
        pack_context(root, tmp_path / "context.tar")


def test_hosted_build_without_vm_registration_never_falls_back_to_docker(tmp_path, monkeypatch):
    monkeypatch.setenv("SKY_REQUIRE_ISOLATED_BUILDS", "true")
    monkeypatch.delenv("SKY_BUILD_SANDBOX_PROFILE_JSON", raising=False)
    with (
        patch("scripts.remote_builder.inputs", return_value=({}, None, {})),
        patch("scripts.remote_builder.command") as docker,
        pytest.raises(ValueError, match="sealed disposable VM"),
    ):
        build(tmp_path, tmp_path / "out")
    docker.assert_not_called()


def test_source_cannot_rebind_vm_account_before_any_aws_clients(tmp_path, monkeypatch):
    import json
    from dataclasses import asdict

    from scripts.vm_build_controller import build_in_vm
    from tests.unit.test_build_sandbox import profile

    p = asdict(profile())
    with patch("boto3.Session") as sessions, pytest.raises(ValueError, match="destination"):
        build_in_vm(
            tmp_path,
            tmp_path / "out",
            {"account_id": "999999999999", "region": p["region"]},
            None,
            {},
            json.dumps(p),
        )
    sessions.assert_not_called()


def test_hosted_api_or_worker_cannot_bypass_vm_via_legacy_image_builder(monkeypatch, tmp_path):
    from adapters.build.image import ImageBuilder

    monkeypatch.setenv("ECS_CONTAINER_METADATA_URI_V4", "http://169.254.170.2/task")
    command = Mock()
    with pytest.raises(ValueError, match="sealed disposable VM"):
        ImageBuilder(command, Mock()).build(tmp_path, Mock(), "forbidden-direct-build")
    command.assert_not_called()
