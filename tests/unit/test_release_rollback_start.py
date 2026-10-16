"""Failed rollback dispatch releases the reservation without claiming a rollback happened."""

from unittest.mock import patch

import pytest

from domain.access import LoginSource, Principal, Role
from interfaces.http.server import App
from tests.regression.test_http_ownership import _handler
from tests.unit.test_release_rollback_scope import releases


@pytest.mark.parametrize("failure_at", ["construct", "start"])
def test_start_failure_preserves_current_release_and_allows_explicit_retry(tmp_path, failure_at):
    app, old_id, new_id = releases(tmp_path)
    before = dict(app.jobs[new_id]["result"])
    for job_id in app.jobs:
        app.save(job_id)
    with patch("interfaces.http.server.threading.Thread") as thread:
        if failure_at == "construct":
            thread.side_effect = RuntimeError("sensitive-internal-detail")
        else:
            thread.return_value.start.side_effect = RuntimeError("sensitive-internal-detail")
        with pytest.raises(ValueError, match="롤백 실행기를 시작하지 못했습니다") as error:
            app.start_release_rollback(new_id)
    assert "sensitive-internal-detail" not in str(error.value)
    assert app.jobs[new_id]["release_rollback_state"] == "failed"
    assert app.jobs[new_id]["status"] == "succeeded"
    assert app.jobs[new_id]["deployment_state"] == "active"
    assert app.jobs[new_id]["result"] == before
    assert app.jobs[old_id]["deployment_state"] == "superseded"
    assert not app.jobs[new_id].get("release_rollback_submitted")
    assert app.jobs[new_id]["events"][-1]["stage"] == "release_rollback_start_failed"
    assert "sensitive-internal-detail" not in str(app.jobs[new_id])
    with app.lock:
        app.ensure_application_available("my-app", "aws-ecs-express")
    restored = App(tmp_path, monitor_interval=0, github_poll_interval=0)
    assert restored.jobs[new_id]["release_rollback_state"] == "failed"
    assert restored.jobs[new_id]["result"] == before
    with patch("interfaces.http.server.threading.Thread") as thread:
        restored.start_release_rollback(new_id)
    thread.return_value.start.assert_called_once()
    assert restored.jobs[new_id]["release_rollback_state"] == "running"


def test_http_does_not_accept_failed_worker_start(tmp_path):
    app, _, new_id = releases(tmp_path)
    principal = Principal("operator", "team_a", Role.DEPLOYER, LoginSource.EXTERNAL_IDP)
    with patch("interfaces.http.server.threading.Thread", side_effect=RuntimeError("private detail")):
        status, payload = _handler(app, principal, f"/api/jobs/{new_id}/rollback-release", method="POST")
    assert status == 400
    assert payload["error"] == "롤백 실행기를 시작하지 못했습니다. 작업 상태를 확인하세요."
    assert app.jobs[new_id]["release_rollback_state"] == "failed"


def test_submitted_work_is_kept_uncertain_if_dispatch_reports_failure(tmp_path):
    app, old_id, new_id = releases(tmp_path)

    def submitted_then_failed():
        app.jobs[new_id]["release_rollback_submitted"] = True
        raise RuntimeError("dispatcher failed after submission")

    with patch("interfaces.http.server.threading.Thread") as thread:
        thread.return_value.start.side_effect = submitted_then_failed
        with pytest.raises(ValueError):
            app.start_release_rollback(new_id)
    assert app.jobs[new_id]["release_rollback_state"] == "needs_attention"
    assert app.jobs[new_id]["deployment_state"] == "needs_attention"
    assert app.jobs[old_id]["deployment_state"] == "superseded"
    with app.lock, pytest.raises(ValueError):
        app.ensure_application_available("my-app", "aws-ecs-express")


def test_completed_worker_result_is_not_overwritten_by_dispatch_exception(tmp_path):
    app, old_id, new_id = releases(tmp_path)

    def completed_then_failed():
        app.finish_release_rollback(new_id, old_id)
        raise RuntimeError("late dispatcher error")

    with patch("interfaces.http.server.threading.Thread") as thread:
        thread.return_value.start.side_effect = completed_then_failed
        with pytest.raises(ValueError):
            app.start_release_rollback(new_id)
    assert app.jobs[new_id]["release_rollback_state"] == "succeeded"
    assert app.jobs[old_id]["deployment_state"] == "active"
    assert app.jobs[new_id]["deployment_state"] == "superseded"
