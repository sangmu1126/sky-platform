"""Deployment verification and predecessor cleanup have separate outcomes."""

import json
from unittest.mock import patch

from application.analysis import AISettings
from application.certificate import deployment_certificate
from interfaces.http.server import App

OLD, NEW = "a" * 16, "b" * 16


def jobs(tmp_path):
    app = App(
        tmp_path,
        AISettings("fixture-key", "fixture-model"),
        monitor_interval=0,
        agent_factory=lambda _: object(),
    )
    project = tmp_path / NEW / "source"
    project.mkdir(parents=True)
    (project / "package.json").write_text('{"scripts":{"start":"node server.js"}}')
    (project / "server.js").write_text("require('http').createServer((q,s)=>s.end('ok')).listen(8080);")
    (tmp_path / OLD).mkdir()
    app.jobs = {
        OLD: {
            "id": OLD,
            "target": "local-docker",
            "status": "succeeded",
            "deployment_state": "active",
            "result": {"url": "http://old.invalid"},
            "events": [],
        },
        NEW: {
            "id": NEW,
            "mode": "agent",
            "target": "local-docker",
            "status": "running",
            "project": str(project),
            "events": [],
            "plan": None,
            "attempts": 0,
            "git_replaces_local_job_id": OLD,
        },
    }
    return app


def test_failed_verification_never_cleans_up_previous_deployment(tmp_path):
    app = jobs(tmp_path)
    with (
        patch("interfaces.http.server.DeploymentAgent") as agent,
        patch.object(app, "retire_replaced_github_local") as cleanup,
    ):
        agent.return_value.run.side_effect = RuntimeError("HTTP verification failed")
        app.run_agent(NEW)
    assert app.jobs[NEW]["status"] == "failed"
    assert "result" not in app.jobs[NEW]
    assert app.jobs[OLD]["deployment_state"] == "active"
    cleanup.assert_not_called()


def test_cleanup_exception_does_not_relabel_verified_deployment_as_failed(tmp_path):
    app = jobs(tmp_path)
    result = {"url": "http://new.invalid"}
    with (
        patch("interfaces.http.server.DeploymentAgent") as agent,
        patch.object(app, "retire_replaced_github_local", side_effect=RuntimeError("cleanup failed")),
    ):
        agent.return_value.run.return_value = result
        app.run_agent(NEW)
    current = app.jobs[NEW]
    assert current["status"] == "succeeded"
    assert current["result"] == result
    assert current["finalization_state"] == "needs_attention"
    assert app.jobs[OLD]["deployment_state"] == "active"
    assert current["events"][-1]["stage"] == "finalization_warning"
    stored = json.loads((tmp_path / NEW / "job.json").read_text())
    assert stored["status"] == "succeeded"
    assert stored["finalization_state"] == "needs_attention"
    assert deployment_certificate(current)["job"]["finalization_state"] == "needs_attention"


def test_predecessor_record_failure_preserves_new_verified_result(tmp_path):
    app = jobs(tmp_path)
    app.jobs[NEW].pop("git_replaces_local_job_id")
    app.jobs[NEW]["replaces_job_id"] = OLD
    save = app.save

    def fail_old_save(job_id):
        if job_id == OLD:
            raise OSError("predecessor record unavailable")
        return save(job_id)

    with patch("interfaces.http.server.DeploymentAgent") as agent, patch.object(app, "save", fail_old_save):
        agent.return_value.run.return_value = {"url": "http://new.invalid"}
        app.run_agent(NEW)
    assert app.jobs[NEW]["status"] == "succeeded"
    assert app.jobs[NEW]["finalization_state"] == "needs_attention"


def test_normal_finalization_runs_only_after_verified_result_is_saved(tmp_path):
    app = jobs(tmp_path)

    def cleanup(job_id):
        assert json.loads((tmp_path / NEW / "job.json").read_text())["status"] == "succeeded"
        app.jobs[OLD]["deployment_state"] = "deleted"

    with (
        patch("interfaces.http.server.DeploymentAgent") as agent,
        patch.object(app, "retire_replaced_github_local", side_effect=cleanup) as retire,
    ):
        agent.return_value.run.return_value = {"url": "http://new.invalid"}
        app.run_agent(NEW)
    retire.assert_called_once_with(NEW)
    assert app.jobs[NEW]["status"] == "succeeded"
    assert app.jobs[OLD]["deployment_state"] == "deleted"


def test_static_cleanup_rechecks_source_scope_before_deletion(tmp_path):
    app = jobs(tmp_path)
    owner = {"organization_id": "team_a", "created_by": "user_1"}
    source = {
        "repository_url": "https://github.com/team/demo",
        "branch": "main",
        "subscription_id": "c" * 16,
        **owner,
    }
    for job in app.jobs.values():
        job.update(
            target="aws-s3-cloudfront",
            status="succeeded",
            deployment_state="active",
            static_stack_id="stack",
            github_source=dict(source),
            **owner,
        )
    app.jobs[NEW]["replaces_job_id"] = OLD
    app.jobs[NEW]["github_source"]["branch"] = "other"
    with patch.object(app, "retire_static_site") as retire:
        app.retire_replaced_github_static(NEW)
    retire.assert_not_called()
    assert app.jobs[OLD]["deployment_state"] == "active"


def test_unconfirmed_cleanup_is_visible_even_if_cleanup_handler_returns(tmp_path):
    app = jobs(tmp_path)
    with (
        patch("interfaces.http.server.DeploymentAgent") as agent,
        patch.object(app, "retire_replaced_github_local", return_value=None),
    ):
        agent.return_value.run.return_value = {"url": "http://new.invalid"}
        app.run_agent(NEW)
    assert app.jobs[NEW]["status"] == "succeeded"
    assert app.jobs[NEW]["finalization_state"] == "needs_attention"
    assert app.jobs[OLD]["deployment_state"] == "active"


def test_restart_preserves_verified_deployment_and_does_not_repeat_pending_cleanup(tmp_path):
    app = jobs(tmp_path)
    app.jobs[NEW].update(
        status="succeeded",
        result={"url": "http://new.invalid"},
        deployment_state="active",
        finalization_state="pending",
    )
    app.save(NEW)
    with patch("application.github_deployments.LocalDockerAdapter") as adapter:
        recovered = App(tmp_path, AISettings("fixture-key", "fixture-model"), monitor_interval=0)
    assert recovered.jobs[NEW]["status"] == "succeeded"
    assert recovered.jobs[NEW]["finalization_state"] == "needs_attention"
    assert recovered.jobs[NEW]["result"]["url"] == "http://new.invalid"
    adapter.assert_not_called()


def test_missing_predecessor_record_is_not_reported_as_completed_finalization(tmp_path):
    app = jobs(tmp_path)
    app.jobs[NEW].pop("git_replaces_local_job_id")
    app.jobs[NEW]["replaces_job_id"] = OLD
    del app.jobs[OLD]
    with patch("interfaces.http.server.DeploymentAgent") as agent:
        agent.return_value.run.return_value = {"url": "http://new.invalid"}
        app.run_agent(NEW)
    assert app.jobs[NEW]["status"] == "succeeded"
    assert app.jobs[NEW]["finalization_state"] == "needs_attention"
