"""A connected GitHub subscription retains deployment control until disconnected."""

from unittest.mock import patch

import pytest

from domain.access import LoginSource, Principal, Role
from tests.regression.test_http_ownership import _handler
from tests.unit.test_github_dispatch_scope import create_pending
from tests.unit.test_github_public_url import FIRST, SECOND, archive
from tests.unit.test_github_retry_integrity import make_app


@pytest.mark.parametrize("enabled", [False, True])
def test_zip_request_is_rejected_before_planning_or_worker_start(tmp_path, enabled):
    app = make_app(tmp_path)
    source_id, job_id = create_pending(app)
    app.jobs[job_id]["status"] = "succeeded"
    app.save(job_id)
    app.set_github_source_enabled(source_id, enabled)
    principal = Principal("operator", "team_a", Role.DEPLOYER, LoginSource.EXTERNAL_IDP)
    with (
        patch("interfaces.http.server.plan_infrastructure") as planner,
        patch.object(app, "start_job_worker") as worker,
    ):
        status, payload = _handler(
            app,
            principal,
            "/api/deployments",
            method="POST",
            body=b"fixture archive",
            headers={"X-Application-Id": "demo-app", "X-Deploy-Target": "local-docker"},
        )
    assert status == 400
    assert "연결을 해제하거나 다른 앱 ID" in payload["error"]
    planner.assert_not_called()
    worker.assert_not_called()
    assert set(app.jobs) == {job_id}
    assert app.jobs[job_id]["status"] == "succeeded"


@pytest.mark.parametrize("mode", ["group", "static", "lambda", "ec2"])
def test_other_reservation_paths_cannot_bypass_source_control(tmp_path, mode):
    app = make_app(tmp_path)
    _, old_id = create_pending(app)
    project = tmp_path / old_id / "source"
    with (
        patch("application.static_deployments.AwsStaticSiteAdapter.preflight") as preflight,
        patch.object(app, "native_unavailable_reason") as native_check,
        patch("interfaces.http.server.inspect_infrastructure") as analysis,
        pytest.raises(ValueError, match="GitHub 자동 배포가 연결"),
    ):
        if mode == "group":
            app.create_deployment_group(project, "demo-app", ["local-docker", "cloud-run"], False)
        elif mode == "static":
            app.create_static_job("f" * 16, project, "demo-app", requested_target="aws-s3-cloudfront")
        else:
            app.create_native_job("f" * 16, project, "demo-app", "aws-" + mode)
    preflight.assert_not_called()
    native_check.assert_not_called()
    analysis.assert_not_called()
    assert set(app.jobs) == {old_id}


def test_connected_push_still_reserves_and_disconnect_releases_control(tmp_path):
    app = make_app(tmp_path)
    source_id, old_id = create_pending(app)
    app.jobs[old_id]["status"] = "failed"
    app.save(old_id)
    with (
        patch("application.github_deployments.resolve_revision", return_value=("main", SECOND)),
        patch("application.github_deployments.download_revision", side_effect=archive),
        patch.object(app, "start_job_worker") as worker,
    ):
        changed = app.poll_github_source(source_id)
    assert changed["changed"] is True
    worker.assert_called_once()
    app.remove_github_source(source_id)
    with app.lock:
        app.ensure_deployment_source_available("demo-app")
    assert app.jobs[old_id]["status"] == "failed"
    assert len(app.jobs) == 2


@pytest.mark.parametrize(
    "field,value", [("branch", "other"), ("organization_id", "team_b"), ("subscription_id", None)]
)
def test_mismatched_github_import_is_rejected_before_download(tmp_path, field, value):
    app = make_app(tmp_path)
    _, job_id = create_pending(app)
    source = dict(app.jobs[job_id]["github_source"])
    source[field] = value
    with app.lock, pytest.raises(ValueError, match="GitHub 자동 배포가 연결"):
        app.ensure_deployment_source_available("demo-app", source)
    with app.lock:
        app.ensure_deployment_source_available("different-app")


def test_one_time_import_cannot_bypass_existing_subscription(tmp_path):
    app = make_app(tmp_path)
    create_pending(app)
    with (
        patch("application.github_deployments.resolve_revision", return_value=("main", FIRST)),
        patch("application.github_deployments.download_revision") as download,
        pytest.raises(ValueError, match="GitHub 자동 배포가 연결"),
    ):
        app.create_github_deployment(
            "https://github.com/team/demo", None, "demo-app", ["local-docker"], False, False
        )
    download.assert_not_called()


def test_binding_does_not_overtake_an_already_pending_manual_job(tmp_path):
    app = make_app(tmp_path)
    # A different target can already be reserved; per-target execution locks alone do not catch it.
    manual_id = "e" * 16
    app.jobs[manual_id] = {
        "id": manual_id,
        "application_id": "demo-app",
        "target": "cloud-run",
        "status": "planned",
    }
    with (
        patch("application.github_deployments.resolve_revision", return_value=("main", FIRST)),
        patch("application.github_deployments.download_revision", side_effect=archive),
        patch.object(app, "start_job_worker") as worker,
        pytest.raises(ValueError, match="다른 배포가 진행 중"),
    ):
        app.create_github_deployment(
            "https://github.com/team/demo", None, "demo-app", ["local-docker"], False, True
        )
    worker.assert_not_called()
    assert set(app.jobs) == {manual_id}
    assert not app.github_sources
    assert not list(tmp_path.glob("*/job.json"))
