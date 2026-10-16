"""Changing source control must not leave provably unstarted reservations blocking uploads."""

from unittest.mock import patch

import pytest

from domain.access import LoginSource, Principal, Role
from tests.regression.test_http_ownership import _handler
from tests.unit.test_github_dispatch_scope import create_pending
from tests.unit.test_github_public_url import FIRST, archive
from tests.unit.test_github_restart_dispatch import group_app
from tests.unit.test_github_retry_integrity import make_app


@pytest.mark.parametrize("operation", ["pause", "disconnect"])
def test_connection_change_eagerly_interrupts_unstarted_job(tmp_path, operation):
    app = make_app(tmp_path)
    source_id, job_id = create_pending(app)
    if operation == "pause":
        app.set_github_source_enabled(source_id, False)
    else:
        app.remove_github_source(source_id)
    assert app.jobs[job_id]["status"] == "interrupted"
    assert app.jobs[job_id]["github_dispatch_blocked"] is True
    with app.lock:
        app.ensure_application_available("demo-app", "local-docker")
    with patch("interfaces.http.server.DeploymentAgent") as agent:
        app.run_agent(job_id)
    agent.assert_not_called()
    restored = make_app(tmp_path)
    assert restored.jobs[job_id]["status"] == "interrupted"
    assert restored.jobs[job_id]["github_dispatch_blocked"] is True
    with restored.lock:
        if operation == "disconnect":
            restored.ensure_deployment_source_available("demo-app")
        else:
            with pytest.raises(ValueError, match="GitHub 자동 배포가 연결"):
                restored.ensure_deployment_source_available("demo-app")


@pytest.mark.parametrize("state", ["admitted", "legacy", "attempted", "succeeded", "waiting_input"])
def test_disconnect_preserves_running_or_uncertain_work(tmp_path, state):
    app = make_app(tmp_path)
    source_id, job_id = create_pending(app)
    job = app.jobs[job_id]
    if state == "admitted":
        with app.lock:
            assert app._admit_github_job_locked(job_id)
    elif state == "legacy":
        job.pop("github_dispatch_generation")
    elif state == "attempted":
        job["attempts"] = 1
    else:
        job["status"] = state
    before = dict(job)
    app.remove_github_source(source_id)
    assert app.jobs[job_id] == before
    assert not app.jobs[job_id].get("github_dispatch_blocked")
    if state != "succeeded":
        with app.lock, pytest.raises(ValueError):
            app.ensure_application_available("demo-app", "local-docker")


def test_disconnect_group_releases_targets_but_delayed_group_cannot_start_old_jobs(tmp_path):
    app = group_app(tmp_path)
    with (
        patch("adapters.gcp.cloud_run.CloudRunSettings.unavailable_reason", return_value=None),
        patch("application.github_deployments.resolve_revision", return_value=("main", FIRST)),
        patch("application.github_deployments.download_revision", side_effect=archive),
        patch.object(app, "start_group_worker"),
    ):
        created = app.create_github_deployment(
            "https://github.com/team/demo", "main", "demo-app", ["local-docker", "cloud-run"], False, True
        )
    app.remove_github_source(created["source_id"])
    with app.lock:
        for target in ("local-docker", "cloud-run"):
            app.ensure_deployment_source_available("demo-app")
            app.ensure_application_available("demo-app", target)
    with patch.object(app, "run_agent") as agent:
        app.run_group(created["deployment"]["id"])
    agent.assert_not_called()
    assert {job["status"] for job in app.jobs.values()} == {"interrupted"}


def test_failed_disconnect_persistence_keeps_connection_and_pending_work(tmp_path):
    app = make_app(tmp_path)
    source_id, job_id = create_pending(app)
    with (
        patch.object(app, "save_github_sources", side_effect=OSError("storage unavailable")),
        pytest.raises(OSError),
    ):
        app.remove_github_source(source_id)
    assert source_id in app.github_sources
    assert app.jobs[job_id]["status"] == "running"
    assert not app.jobs[job_id].get("github_dispatch_blocked")


def test_failed_pause_persistence_does_not_interrupt_pending_work(tmp_path):
    app = make_app(tmp_path)
    source_id, job_id = create_pending(app)
    with (
        patch.object(app, "save_github_sources", side_effect=OSError("storage unavailable")),
        pytest.raises(OSError),
    ):
        app.set_github_source_enabled(source_id, False)
    assert app.github_sources[source_id]["enabled"] is True
    assert app.jobs[job_id]["status"] == "running"


def test_repeated_pause_does_not_duplicate_interruption_events(tmp_path):
    app = make_app(tmp_path)
    source_id, job_id = create_pending(app)
    app.set_github_source_enabled(source_id, False)
    count = len(app.jobs[job_id]["events"])
    app.set_github_source_enabled(source_id, False)
    assert len(app.jobs[job_id]["events"]) == count


def test_disconnect_then_zip_upload_accepts_new_job_and_blocks_delayed_old_worker(tmp_path):
    app = make_app(tmp_path)
    source_id, old_id = create_pending(app)
    app.remove_github_source(source_id)
    upload = tmp_path / "manual.zip"
    archive(None, FIRST, upload)
    principal = Principal("operator", "team_a", Role.DEPLOYER, LoginSource.EXTERNAL_IDP)
    with patch.object(app, "start_job_worker", return_value=True) as start:
        status, result = _handler(
            app,
            principal,
            "/api/deployments",
            method="POST",
            body=upload.read_bytes(),
            headers={"X-Application-Id": "demo-app", "X-Deploy-Target": "local-docker"},
        )
    assert status == 202
    new_id = result["id"]
    assert new_id != old_id
    assert "github_source" not in app.jobs[new_id]
    assert app.jobs[new_id]["status"] == "running"
    start.assert_called_once()
    with patch("interfaces.http.server.DeploymentAgent") as agent:
        app.run_agent(old_id)
    agent.assert_not_called()
    assert app.jobs[old_id]["status"] == "interrupted"
    assert app.jobs[new_id]["status"] == "running"
