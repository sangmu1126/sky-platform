"""GitHub dispatch failures retain retryable records without a pending-job dead end."""

from unittest.mock import patch

import pytest

from tests.unit.test_github_public_url import FIRST, archive
from tests.unit.test_github_restart_dispatch import group_app
from tests.unit.test_github_retry_integrity import make_app


@pytest.mark.parametrize("failure_at", ["construct", "start"])
def test_group_start_failure_is_persisted_and_explicitly_retryable(tmp_path, failure_at):
    app = group_app(tmp_path)
    with (
        patch("adapters.gcp.cloud_run.CloudRunSettings.unavailable_reason", return_value=None),
        patch("application.github_deployments.resolve_revision", return_value=("main", FIRST)),
        patch("application.github_deployments.download_revision", side_effect=archive),
        patch("interfaces.http.server.threading.Thread") as thread,
    ):
        if failure_at == "construct":
            thread.side_effect = RuntimeError("private worker detail")
        else:
            thread.return_value.start.side_effect = RuntimeError("private worker detail")
        with pytest.raises(ValueError, match="실행기를 시작하지 못했습니다") as error:
            app.create_github_deployment(
                "https://github.com/team/demo", "main", "demo-app", ["local-docker", "cloud-run"], False, True
            )
    assert "private worker detail" not in str(error.value)
    assert not app.active_groups
    assert {job["status"] for job in app.jobs.values()} == {"interrupted"}
    assert all(job["github_dispatch_blocked"] is True for job in app.jobs.values())
    assert "private worker detail" not in str(app.jobs)
    summary = app.github_source_summaries()[0]
    assert summary["last_deployment_status"] == "blocked"
    assert summary["enabled"] and summary["retryable"]
    old_ids = set(app.jobs)
    restored = group_app(tmp_path)
    assert {job["status"] for job in restored.jobs.values()} == {"interrupted"}
    with (
        patch("adapters.gcp.cloud_run.CloudRunSettings.unavailable_reason", return_value=None),
        patch("application.github_deployments.resolve_revision", return_value=("main", FIRST)),
        patch("application.github_deployments.download_revision", side_effect=archive),
        patch.object(restored, "start_group_worker") as start,
    ):
        result = restored.poll_github_source(summary["id"], retry_failed=True)
    assert result["changed"] is True
    assert old_ids.isdisjoint(result["job_ids"])
    start.assert_called_once()


@pytest.mark.parametrize("existing_status", ["succeeded", "running"])
def test_group_failure_preserves_completed_or_running_children(tmp_path, existing_status):
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
    first, second = created["deployment"]["targets"]
    app.jobs[first["job_id"]].update(status=existing_status, result={"url": "http://preserved.invalid"})
    app.save(first["job_id"])
    with (
        patch("interfaces.http.server.threading.Thread", side_effect=RuntimeError("start failed")),
        pytest.raises(ValueError),
    ):
        app.start_group_worker(created["deployment"]["id"])
    assert app.jobs[first["job_id"]]["status"] == existing_status
    assert app.jobs[first["job_id"]]["result"]["url"] == "http://preserved.invalid"
    assert app.jobs[second["job_id"]]["status"] == "interrupted"


def test_duplicate_group_start_does_not_interrupt_active_work(tmp_path):
    app = group_app(tmp_path)
    app.active_groups.add("already-running")
    with patch("interfaces.http.server.threading.Thread") as thread:
        assert app.start_group_worker("already-running") is False
    thread.assert_not_called()
    assert "already-running" in app.active_groups


def test_single_start_failure_is_not_returned_as_a_started_deployment(tmp_path):
    app = make_app(tmp_path)
    with (
        patch("application.github_deployments.resolve_revision", return_value=("main", FIRST)),
        patch("application.github_deployments.download_revision", side_effect=archive),
        patch("interfaces.http.server.threading.Thread", side_effect=RuntimeError("private detail")),
        pytest.raises(ValueError, match="GitHub 배포 실행기를 시작하지 못했습니다"),
    ):
        app.create_github_deployment(
            "https://github.com/team/demo", "main", "demo-app", ["local-docker"], False, True
        )
    summary = app.github_source_summaries()[0]
    assert summary["retryable"] is True
    assert summary["last_deployment_status"] == "failed"
    assert {job["status"] for job in app.jobs.values()} == {"interrupted"}
