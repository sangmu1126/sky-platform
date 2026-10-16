"""Restart stops subscribed group queues without guessing whether deployment finished."""

from unittest.mock import patch

import pytest

from adapters.gcp.cloud_run import CloudRunSettings
from application.analysis import AISettings
from interfaces.http.server import App
from tests.unit.test_github_dispatch_scope import create_pending
from tests.unit.test_github_public_url import FIRST, archive
from tests.unit.test_github_retry_integrity import make_app


def group_app(root):
    return App(
        root,
        AISettings("fixture-key", "fixture-model"),
        cloud_settings=CloudRunSettings("demo-project", "asia-northeast3"),
        monitor_interval=0,
        github_poll_interval=60,
    )


@pytest.mark.parametrize("completed_first", [False, True])
def test_restart_interrupts_pending_group_and_allows_explicit_retry(tmp_path, completed_first):
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
    old_ids = set(app.jobs)
    assert {job["status"] for job in app.jobs.values()} == {"planned"}
    completed_id = next(iter(app.jobs)) if completed_first else None
    if completed_id:
        app.jobs[completed_id].update(status="succeeded", result={"url": "http://existing.invalid"})
        app.save(completed_id)
    pending_ids = old_ids - ({completed_id} if completed_id else set())
    with patch("interfaces.http.server.threading.Thread") as thread:
        restored = group_app(tmp_path)
    thread.assert_not_called()
    assert all(restored.jobs[job_id]["status"] == "interrupted" for job_id in pending_ids)
    assert all(restored.jobs[job_id]["github_dispatch_blocked"] is True for job_id in pending_ids)
    if completed_id:
        assert restored.jobs[completed_id]["status"] == "succeeded"
        assert restored.jobs[completed_id]["result"] == {"url": "http://existing.invalid"}
    assert restored.github_source_summaries()[0]["last_deployment_status"] == "blocked"
    with patch("interfaces.http.server.DeploymentAgent") as agent:
        for job_id in pending_ids:
            restored.run_agent(job_id)
    agent.assert_not_called()
    assert not any(job.get("github_dispatch_admitted") for job in restored.jobs.values())
    again = group_app(tmp_path)
    assert all(
        len(again.jobs[job_id]["events"]) == len(restored.jobs[job_id]["events"]) for job_id in old_ids
    )
    with (
        patch("adapters.gcp.cloud_run.CloudRunSettings.unavailable_reason", return_value=None),
        patch("application.github_deployments.resolve_revision", return_value=("main", FIRST)),
        patch("application.github_deployments.download_revision", side_effect=archive) as download,
        patch.object(again, "start_group_worker") as worker,
    ):
        assert again.poll_github_source(created["source_id"])["changed"] is False
        download.assert_not_called()
        worker.assert_not_called()
        retried = again.poll_github_source(created["source_id"], retry_failed=True)
    assert retried["changed"] is True
    assert old_ids.isdisjoint(retried["job_ids"])
    worker.assert_called_once()


@pytest.mark.parametrize("admitted", [False, True])
def test_running_job_is_interrupted_without_claiming_execution_did_not_happen(tmp_path, admitted):
    app = make_app(tmp_path)
    _, job_id = create_pending(app)
    app.jobs[job_id]["github_dispatch_admitted"] = admitted
    app.save(job_id)
    restored = make_app(tmp_path)
    assert restored.jobs[job_id]["status"] == "interrupted"
    assert not restored.jobs[job_id].get("github_dispatch_blocked")
    assert "완료 여부를 확인하지 못했습니다" in restored.jobs[job_id]["events"][-1]["message"]


@pytest.mark.parametrize(
    "updates",
    [
        {"github_dispatch_generation": True},
        {"github_dispatch_generation": -1},
        {"github_dispatch_generation": "0"},
        {"github_dispatch_admitted": "false"},
        {"github_dispatch_blocked": 1},
        {"github_dispatch_admitted": True, "github_dispatch_blocked": True},
        {"github_source": {"subscription_id": "invalid"}},
    ],
)
def test_invalid_dispatch_record_is_not_restored(tmp_path, updates):
    app = make_app(tmp_path)
    _, job_id = create_pending(app)
    app.jobs[job_id].update(updates)
    app.save(job_id)
    restored = make_app(tmp_path)
    assert job_id not in restored.jobs
    assert restored.recovery_warnings
    summary = restored.github_source_summaries()[0]
    assert summary["last_deployment_status"] == "unknown"
    assert summary["retryable"] is False


def test_legacy_subscribed_queue_is_interrupted_without_dispatch_fields(tmp_path):
    app = make_app(tmp_path)
    _, job_id = create_pending(app)
    app.jobs[job_id].pop("github_dispatch_generation")
    app.jobs[job_id]["status"] = "planned"
    app.save(job_id)
    restored = make_app(tmp_path)
    assert restored.jobs[job_id]["status"] == "interrupted"
    assert restored.github_source_summaries()[0]["retryable"] is True
    assert job_id in make_app(tmp_path).jobs


def test_non_github_planned_work_keeps_existing_explicit_resume_behavior(tmp_path):
    app = make_app(tmp_path)
    _, job_id = create_pending(app)
    app.jobs[job_id].pop("github_dispatch_generation")
    app.jobs[job_id].pop("github_source")
    app.jobs[job_id]["status"] = "planned"
    app.save(job_id)
    assert make_app(tmp_path).jobs[job_id]["status"] == "planned"
