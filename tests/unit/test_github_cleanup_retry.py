"""Explicit cleanup retry checks both resources and serializes deletion attempts."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event
from unittest.mock import patch

import pytest

from domain.access import LoginSource, Principal, Role
from tests.regression.test_http_ownership import _handler
from tests.unit.test_github_release_scope import OWNER, app_and_project, release

OLD, NEW = "b" * 16, "c" * 16


@pytest.fixture(autouse=True)
def healthy_current():
    with patch("application.github_deployments.check_deployment", return_value={"healthy": True}) as probe:
        yield probe


def app_with_cleanup(tmp_path):
    app, _ = app_and_project(tmp_path)
    old, new = release(OLD, "local-docker"), release(NEW, "local-docker")
    new.update(finalization_state="needs_attention", git_replaces_local_job_id=OLD, events=[])
    app.jobs = {OLD: old, NEW: new}
    (tmp_path / OLD).mkdir()
    (tmp_path / NEW).mkdir()
    return app


def test_retry_only_retires_previous_release_and_preserves_current_result(tmp_path):
    app = app_with_cleanup(tmp_path)
    with patch("application.github_deployments.LocalDockerAdapter") as adapter:
        result = app.retry_github_local_cleanup(NEW)
    adapter.return_value.retire.assert_called_once_with(app.jobs[OLD]["result"], OLD)
    assert result["finalization_state"] == "complete"
    assert app.jobs[OLD]["deployment_state"] == "deleted"
    assert app.jobs[NEW]["status"] == "succeeded"
    assert app.jobs[NEW]["result"] == {"service": "old-service"}


def test_failed_retry_preserves_success_and_allows_another_explicit_attempt(tmp_path):
    app = app_with_cleanup(tmp_path)
    with patch("application.github_deployments.LocalDockerAdapter") as adapter:
        adapter.return_value.retire.side_effect = RuntimeError("Docker unavailable")
        result = app.retry_github_local_cleanup(NEW)
    assert result["finalization_state"] == "needs_attention"
    assert app.jobs[OLD]["deployment_state"] == "active"
    assert app.jobs[NEW]["status"] == "succeeded"


def test_already_deleted_predecessor_needs_no_second_docker_deletion(tmp_path):
    app = app_with_cleanup(tmp_path)
    app.jobs[OLD]["deployment_state"] = "deleted"
    with patch("application.github_deployments.LocalDockerAdapter") as adapter:
        assert app.retry_github_local_cleanup(NEW)["finalization_state"] == "complete"
    adapter.assert_not_called()


@pytest.mark.parametrize(
    "field,value",
    [
        ("target", "aws-ecs-express"),
        ("status", "failed"),
        ("finalization_state", "pending"),
    ],
)
def test_ineligible_retry_never_reaches_docker(tmp_path, field, value):
    app = app_with_cleanup(tmp_path)
    app.jobs[NEW][field] = value
    with patch("application.github_deployments.LocalDockerAdapter") as adapter, pytest.raises(ValueError):
        app.retry_github_local_cleanup(NEW)
    adapter.assert_not_called()


def test_changed_source_scope_blocks_retry(tmp_path):
    app = app_with_cleanup(tmp_path)
    app.jobs[OLD]["github_source"]["branch"] = "other"
    with patch("application.github_deployments.LocalDockerAdapter") as adapter, pytest.raises(ValueError):
        app.retry_github_local_cleanup(NEW)
    adapter.assert_not_called()


def test_parallel_retry_only_starts_one_docker_operation(tmp_path):
    app = app_with_cleanup(tmp_path)
    entered, release_call = Event(), Event()

    def retire(*args):
        entered.set()
        assert release_call.wait(5)

    with (
        patch("application.github_deployments.LocalDockerAdapter") as adapter,
        ThreadPoolExecutor(1) as executor,
    ):
        adapter.return_value.retire.side_effect = retire
        future = executor.submit(app.retry_github_local_cleanup, NEW)
        try:
            assert entered.wait(5)
            with pytest.raises(ValueError):
                app.retry_github_local_cleanup(NEW)
        finally:
            release_call.set()
        assert future.result(timeout=5)["finalization_state"] == "complete"
    assert adapter.return_value.retire.call_count == 1


@pytest.mark.parametrize(
    "role,organization,expected",
    [
        (Role.VIEWER, "team_a", 403),
        (Role.DEPLOYER, "team_a", 403),
        (Role.ADMIN, "other", 404),
    ],
)
def test_http_requires_delete_permission_on_current_release(tmp_path, role, organization, expected):
    app = app_with_cleanup(tmp_path)
    actor = Principal("user_1", organization, role, LoginSource.EXTERNAL_IDP)
    with patch.object(app, "retry_github_local_cleanup") as retry:
        assert _handler(app, actor, f"/api/jobs/{NEW}/finalization/retry", method="POST")[0] == expected
    retry.assert_not_called()


def test_http_checks_predecessor_ownership_before_retry(tmp_path):
    app = app_with_cleanup(tmp_path)
    app.jobs[OLD].update(organization_id="foreign")
    actor = Principal(OWNER["created_by"], "team_a", Role.ADMIN, LoginSource.EXTERNAL_IDP)
    with patch.object(app, "retry_github_local_cleanup") as retry:
        assert _handler(app, actor, f"/api/jobs/{NEW}/finalization/retry", method="POST")[0] == 404
    retry.assert_not_called()


def test_authorized_http_retry_reaches_cleanup(tmp_path):
    app = app_with_cleanup(tmp_path)
    actor = Principal("user_1", "team_a", Role.ADMIN, LoginSource.EXTERNAL_IDP)
    with patch("application.github_deployments.LocalDockerAdapter"):
        status, result = _handler(app, actor, f"/api/jobs/{NEW}/finalization/retry", method="POST")
    assert status == 200
    assert result["finalization_state"] == "complete"


def test_unhealthy_current_service_preserves_predecessor(tmp_path, healthy_current):
    app = app_with_cleanup(tmp_path)
    healthy_current.return_value = {"healthy": False}
    with patch("application.github_deployments.LocalDockerAdapter") as adapter:
        result = app.retry_github_local_cleanup(NEW)
    adapter.assert_not_called()
    assert result["finalization_state"] == "needs_attention"
    assert app.jobs[OLD]["deployment_state"] == "active"


def test_changed_current_result_during_probe_blocks_deletion(tmp_path, healthy_current):
    app = app_with_cleanup(tmp_path)

    def changed(snapshot):
        app.jobs[NEW]["result"] = {"url": "http://different.invalid"}
        return {"healthy": True}

    healthy_current.side_effect = changed
    with patch("application.github_deployments.LocalDockerAdapter") as adapter:
        result = app.retry_github_local_cleanup(NEW)
    adapter.assert_not_called()
    assert result["finalization_state"] == "needs_attention"


def test_body_is_rejected_before_retry(tmp_path):
    app = app_with_cleanup(tmp_path)
    actor = Principal("user_1", "team_a", Role.ADMIN, LoginSource.EXTERNAL_IDP)
    with patch.object(app, "retry_github_local_cleanup") as retry:
        status, _ = _handler(app, actor, f"/api/jobs/{NEW}/finalization/retry", method="POST", body=b"{}")
    assert status == 400
    retry.assert_not_called()


def test_changed_predecessor_pointer_during_probe_blocks_deletion(tmp_path, healthy_current):
    app = app_with_cleanup(tmp_path)
    extra = release("d" * 16, "local-docker")
    app.jobs[extra["id"]] = extra

    def changed(snapshot):
        app.jobs[NEW]["git_replaces_local_job_id"] = extra["id"]
        return {"healthy": True}

    healthy_current.side_effect = changed
    with patch("application.github_deployments.LocalDockerAdapter") as adapter:
        assert app.retry_github_local_cleanup(NEW)["finalization_state"] == "needs_attention"
    adapter.assert_not_called()
    assert app.jobs[OLD]["deployment_state"] == app.jobs[extra["id"]]["deployment_state"] == "active"
