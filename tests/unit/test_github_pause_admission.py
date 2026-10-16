"""Pause invalidates queued GitHub work, even if the connection resumes later."""

from unittest.mock import patch

import pytest

from tests.unit.test_github_public_url import FIRST, SECOND, archive
from tests.unit.test_github_retry_integrity import create_failed, make_app


@pytest.mark.parametrize("action", ["pause", "pause_resume", "disconnect"])
@pytest.mark.parametrize("static", [False, True])
def test_connection_change_before_worker_entry_prevents_external_work(tmp_path, action, static):
    app = make_app(tmp_path)
    with (
        patch("application.github_deployments.resolve_revision", return_value=("main", FIRST)),
        patch("application.github_deployments.download_revision", side_effect=archive),
        patch.object(app, "start_job_worker"),
    ):
        source_id, job_id = create_failed(app)
    app.jobs[job_id]["status"] = "running"
    if action == "disconnect":
        app.remove_github_source(source_id)
    else:
        app.set_github_source_enabled(source_id, False)
        if action == "pause_resume":
            app.set_github_source_enabled(source_id, True)
    with (
        patch("interfaces.http.server.DeploymentAgent") as agent,
        patch.object(app, "static_adapter") as adapter,
    ):
        (app.run_static_site if static else app.run_agent)(job_id)
    agent.assert_not_called()
    adapter.assert_not_called()
    assert app.jobs[job_id]["status"] == "interrupted"
    restored = make_app(tmp_path)
    assert restored.jobs[job_id]["status"] == "interrupted"


def test_pause_resume_during_download_discards_unpublished_jobs(tmp_path):
    app = make_app(tmp_path)
    with (
        patch("application.github_deployments.resolve_revision", return_value=("main", FIRST)),
        patch("application.github_deployments.download_revision", side_effect=archive),
        patch.object(app, "start_job_worker") as worker,
    ):
        source_id, old_id = create_failed(app)

        def changed_connection(repository, commit, destination):
            app.set_github_source_enabled(source_id, False)
            app.set_github_source_enabled(source_id, True)
            archive(repository, commit, destination)

        with (
            patch("application.github_deployments.resolve_revision", return_value=("main", SECOND)),
            patch("application.github_deployments.download_revision", side_effect=changed_connection),
            pytest.raises(ValueError, match="設定|설정이 변경"),
        ):
            app.poll_github_source(source_id)
    assert set(app.jobs) == {old_id}
    assert app.github_sources[source_id]["last_revision"] == FIRST
    assert worker.call_count == 1


def test_pause_after_publication_before_worker_entry_blocks_new_revision(tmp_path):
    app = make_app(tmp_path)
    with (
        patch("application.github_deployments.resolve_revision", return_value=("main", FIRST)),
        patch("application.github_deployments.download_revision", side_effect=archive),
        patch.object(app, "start_job_worker"),
    ):
        source_id, old_id = create_failed(app)
    with (
        patch("application.github_deployments.resolve_revision", return_value=("main", SECOND)),
        patch("application.github_deployments.download_revision", side_effect=archive),
        patch.object(
            app, "start_job_worker", side_effect=lambda *_: app.set_github_source_enabled(source_id, False)
        ),
    ):
        result = app.poll_github_source(source_id)
    job_id = result["job_ids"][0]
    app.run_agent(job_id)
    assert app.jobs[job_id]["status"] == "interrupted"
    assert app.jobs[old_id]["status"] == "failed"


def test_admitted_job_is_not_cancelled_by_polling_pause(tmp_path):
    app = make_app(tmp_path)
    with (
        patch("application.github_deployments.resolve_revision", return_value=("main", FIRST)),
        patch("application.github_deployments.download_revision", side_effect=archive),
        patch.object(app, "start_job_worker"),
    ):
        source_id, job_id = create_failed(app)
    with app.lock:
        assert app._admit_github_job_locked(job_id)
    app.set_github_source_enabled(source_id, False)
    with app.lock:
        assert app._admit_github_job_locked(job_id)
    assert app.jobs[job_id]["status"] == "failed"


def test_group_checks_pause_before_each_target(tmp_path):
    app = make_app(tmp_path)
    source_id = "a" * 16
    app.github_sources[source_id] = {"enabled": True}
    for order in range(2):
        job_id = str(order) * 16
        app.jobs[job_id] = {
            "id": job_id,
            "group_id": "group",
            "group_order": order,
            "target": "local-docker",
            "status": "planned",
            "events": [],
            "github_source": {"subscription_id": source_id},
            "github_dispatch_generation": 0,
        }

    def first_target(job_id):
        app.jobs[job_id]["status"] = "succeeded"
        app.set_github_source_enabled(source_id, False)

    with (
        patch.object(app, "save"),
        patch.object(app, "save_github_sources"),
        patch.object(app, "run_agent", side_effect=first_target) as worker,
    ):
        app.run_group("group")
    assert worker.call_count == 1
    assert app.jobs["0" * 16]["status"] == "succeeded"
    assert app.jobs["1" * 16]["status"] == "interrupted"


def test_failed_pause_persistence_restores_dispatch_generation(tmp_path):
    app = make_app(tmp_path)
    app.github_sources["source"] = {"enabled": True}
    with patch.object(app, "save_github_sources", side_effect=OSError("disk")), pytest.raises(OSError):
        app.set_github_source_enabled("source", False)
    assert app.github_sources["source"] == {"enabled": True}


def test_explicit_retry_after_resume_uses_current_generation(tmp_path):
    app = make_app(tmp_path)
    with (
        patch("application.github_deployments.resolve_revision", return_value=("main", FIRST)),
        patch("application.github_deployments.download_revision", side_effect=archive),
        patch.object(app, "start_job_worker"),
    ):
        source_id, old_id = create_failed(app)
        app.set_github_source_enabled(source_id, False)
        app.set_github_source_enabled(source_id, True)
        retried = app.poll_github_source(source_id, retry_failed=True)
    new_id = retried["job_ids"][0]
    assert new_id != old_id
    assert app.jobs[new_id]["github_dispatch_generation"] == 2
    with app.lock:
        assert app._admit_github_job_locked(new_id)
    assert app.jobs[new_id]["github_dispatch_admitted"] is True
    restored = make_app(tmp_path)
    assert restored.github_sources[source_id]["dispatch_generation"] == 2


def test_blocked_summary_survives_restart_and_resume_requires_explicit_retry(tmp_path):
    app = make_app(tmp_path)
    with (
        patch("application.github_deployments.resolve_revision", return_value=("main", FIRST)),
        patch("application.github_deployments.download_revision", side_effect=archive),
        patch.object(app, "start_job_worker"),
    ):
        source_id, job_id = create_failed(app)
    app.set_github_source_enabled(source_id, False)
    app.run_agent(job_id)
    restored = make_app(tmp_path)
    summary = restored.github_source_summaries()[0]
    assert summary["last_deployment_status"] == "blocked"
    assert summary["retryable"] is True
    restored.set_github_source_enabled(source_id, True)
    with (
        patch("application.github_deployments.resolve_revision", return_value=("main", FIRST)),
        patch("application.github_deployments.download_revision", side_effect=archive) as download,
        patch.object(restored, "start_job_worker") as worker,
    ):
        assert restored.poll_github_source(source_id)["changed"] is False
        download.assert_not_called()
        worker.assert_not_called()
        result = restored.poll_github_source(source_id, retry_failed=True)
    assert result["changed"] is True
    worker.assert_called_once()
    assert restored.jobs[job_id]["status"] == "interrupted"
    assert restored.github_source_summaries()[0]["last_deployment_status"] == "running"


@pytest.mark.parametrize(
    "others,expected,retryable",
    [
        (["succeeded"], "blocked", True),
        (["failed"], "failed", True),
        (["interrupted"], "failed", True),
        (["running"], "failed", False),
        (["missing"], "unknown", False),
    ],
)
def test_blocked_group_does_not_hide_other_failure_or_unfinished_work(tmp_path, others, expected, retryable):
    app = make_app(tmp_path)
    ids = ["0" * 16, "1" * 16]
    app.github_sources["source"] = {"last_job_ids": ids}
    app.jobs[ids[0]] = {"status": "interrupted", "github_dispatch_blocked": True}
    if others[0] != "missing":
        app.jobs[ids[1]] = {"status": others[0]}
    summary = app.github_source_summaries()[0]
    assert summary["last_deployment_status"] == expected
    assert summary["retryable"] is retryable
