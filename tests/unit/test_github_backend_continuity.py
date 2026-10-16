"""A push may update a backend, but cannot silently move an active subscription."""

from unittest.mock import patch

import pytest

from application.analysis import AISettings
from interfaces.http.server import App
from tests.unit.test_github_public_url import FIRST, SECOND, archive


@pytest.mark.parametrize(
    "previous,proposed",
    [
        ("local-docker", "aws-ecs-express"),
        ("aws-ecs-express", "cloud-run"),
        ("cloud-run", "local-docker"),
        ("local-docker", "local-docker"),
        ("aws-ecs-express", "aws-ecs-express"),
        ("cloud-run", "cloud-run"),
    ],
)
def test_subscription_updates_same_backend_and_blocks_backend_changes(tmp_path, previous, proposed):
    choices = iter([previous, proposed])

    class Planner:
        def __init__(self, settings):
            pass

        def propose(self, files, targets, public):
            return {
                "target": next(choices),
                "workload": "stateless-http",
                "rationale": "검증용 후보 선택",
                "evidence": [{"file": "server.js", "quote": "createServer"}],
            }

    app = App(
        tmp_path,
        AISettings("fixture-key", "fixture-model"),
        monitor_interval=0,
        github_poll_interval=60,
        infrastructure_planner_factory=Planner,
    )
    with (
        patch(
            "application.github_deployments.resolve_revision",
            side_effect=[
                ("main", FIRST),
                ("main", SECOND),
            ],
        ),
        patch("application.github_deployments.download_revision", side_effect=archive),
        patch("interfaces.http.server.AwsSettings.unavailable_reason", return_value=None),
        patch("interfaces.http.server.CloudRunSettings.unavailable_reason", return_value=None),
        patch.object(app, "start_job_worker", return_value=True) as worker,
    ):
        created = app.create_github_deployment(
            "https://github.com/team/demo", None, "demo-app", ["auto"], True, True
        )
        source_id = created["source_id"]
        old_id = created["deployment"]["id"]
        app.jobs[old_id].update(status="succeeded", deployment_state="active")
        if previous == proposed:
            changed = app.poll_github_source(source_id)
            assert changed["changed"] is True
            assert app.jobs[changed["job_ids"][0]]["target"] == previous
            assert app.github_sources[source_id]["last_revision"] == SECOND
            assert worker.call_count == 2
            return
        with pytest.raises(ValueError, match="수동 확인"):
            app.poll_github_source(source_id)
    assert set(app.jobs) == {old_id}
    assert app.jobs[old_id]["deployment_state"] == "active"
    assert app.github_sources[source_id]["last_revision"] == FIRST
    assert app.github_sources[source_id]["last_job_ids"] == [old_id]
    assert previous in app.github_sources[source_id]["last_error"]
    assert proposed in app.github_sources[source_id]["last_error"]
    assert worker.call_count == 1


def test_missing_configuration_for_active_backend_never_invokes_replacement_planner(tmp_path):
    class Planner:
        calls = 0

        def __init__(self, settings):
            pass

        def propose(self, files, targets, public):
            Planner.calls += 1
            return {
                "target": "aws-ecs-express",
                "workload": "stateless-http",
                "rationale": "AWS 선택",
                "evidence": [{"file": "server.js", "quote": "createServer"}],
            }

    app = App(
        tmp_path,
        AISettings("fixture-key", "fixture-model"),
        monitor_interval=0,
        github_poll_interval=60,
        infrastructure_planner_factory=Planner,
    )
    with (
        patch(
            "application.github_deployments.resolve_revision",
            side_effect=[
                ("main", FIRST),
                ("main", SECOND),
            ],
        ),
        patch("application.github_deployments.download_revision", side_effect=archive),
        patch("interfaces.http.server.CloudRunSettings.unavailable_reason", return_value=None),
        patch("interfaces.http.server.AwsSettings.unavailable_reason", return_value=None) as aws,
        patch.object(app, "start_job_worker", return_value=True),
    ):
        created = app.create_github_deployment(
            "https://github.com/team/demo", None, "demo-app", ["auto"], True, True
        )
        old_id = created["deployment"]["id"]
        app.jobs[old_id].update(status="succeeded", deployment_state="active")
        aws.return_value = "configuration removed"
        with pytest.raises(ValueError, match="수동 확인"):
            app.poll_github_source(created["source_id"])
    assert Planner.calls == 1
    assert app.github_sources[created["source_id"]]["last_revision"] == FIRST
    assert app.jobs[old_id]["deployment_state"] == "active"


def test_backend_is_rechecked_under_reservation_lock_after_model_returns(tmp_path):
    class Planner:
        def __init__(self, settings):
            pass

        def propose(self, files, targets, public):
            # Simulate another deployment becoming active during the model call.
            app.jobs["c" * 16] = {
                "application_id": "demo-app",
                "target": "cloud-run",
                "status": "succeeded",
                "deployment_state": "active",
                "github_source": {"subscription_id": subscription_id},
            }
            return {
                "target": "local-docker",
                "workload": "stateless-http",
                "rationale": "로컬 선택",
                "evidence": [{"file": "server.js", "quote": "createServer"}],
            }

    app = App(
        tmp_path,
        AISettings("fixture-key", "fixture-model"),
        monitor_interval=0,
        infrastructure_planner_factory=Planner,
    )
    subscription_id = "b" * 16
    project = tmp_path / "input"
    project.mkdir()
    (project / "server.js").write_text("require('http').createServer((q,s)=>s.end('ok')).listen(8080);")
    with (
        patch("interfaces.http.server.AwsSettings.unavailable_reason", return_value=None),
        patch("interfaces.http.server.CloudRunSettings.unavailable_reason", return_value=None),
        pytest.raises(ValueError, match="수동 확인"),
    ):
        app._reserve_single_github_job(
            project, "demo-app", "auto", True, {"subscription_id": subscription_id}
        )
    assert set(app.jobs) == {"c" * 16}
    assert not list(tmp_path.glob("*/job.json"))


def test_inactive_or_unrelated_jobs_do_not_pin_subscription_backend():
    from application.github_deployments import _active_subscription_backend

    base = {
        "application_id": "demo-app",
        "target": "cloud-run",
        "status": "succeeded",
        "deployment_state": "active",
        "github_source": {"subscription_id": "a" * 16},
    }
    jobs = [
        {**base, "status": "failed"},
        {**base, "deployment_state": "deleted"},
        {**base, "github_source": {"subscription_id": "b" * 16}},
        {**base, "application_id": "other-app"},
    ]
    assert _active_subscription_backend(jobs, "demo-app", "a" * 16) is None
    assert _active_subscription_backend([base], "demo-app", None) is None
    with pytest.raises(ValueError, match="여러 활성 백엔드"):
        _active_subscription_backend([base, {**base, "target": "local-docker"}], "demo-app", "a" * 16)
