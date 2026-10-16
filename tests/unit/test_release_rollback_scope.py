"""Explicit rollback must not cross source or organization boundaries."""

import json
from unittest.mock import patch

import pytest

from domain.access import LoginSource, Principal, Role
from tests.regression import test_aws_releases as aws_fixtures
from tests.regression.test_http_ownership import _handler


def releases(tmp_path):
    app, old_id, new_id = aws_fixtures.AwsReleaseTests().completed_release(tmp_path)
    for job in app.jobs.values():
        job.update(organization_id="team_a", created_by="creator")
    return app, old_id, new_id


@pytest.mark.parametrize("explicit", [False, True])
def test_http_rejects_foreign_previous_release_before_worker(tmp_path, explicit):
    app, old_id, new_id = releases(tmp_path)
    app.jobs[old_id]["organization_id"] = "team_b"
    principal = Principal("operator", "team_a", Role.DEPLOYER, LoginSource.EXTERNAL_IDP)
    body = json.dumps({"target_job_id": old_id}).encode() if explicit else b""
    with patch.object(app, "start_release_rollback") as worker:
        status, payload = _handler(
            app, principal, f"/api/jobs/{new_id}/rollback-release", method="POST", body=body
        )
    assert (status, payload) == (404, {"error": "Not found"})
    worker.assert_not_called()


def test_http_reconcile_rejects_foreign_previous_release(tmp_path):
    app, old_id, new_id = releases(tmp_path)
    app.jobs[new_id]["release_rollback_target_id"] = old_id
    app.jobs[old_id]["organization_id"] = "team_b"
    principal = Principal("operator", "team_a", Role.DEPLOYER, LoginSource.EXTERNAL_IDP)
    with patch.object(app, "reconcile_release_rollback") as reconcile:
        assert (
            _handler(app, principal, f"/api/jobs/{new_id}/rollback-release/reconcile", method="POST")[0]
            == 404
        )
    reconcile.assert_not_called()


@pytest.mark.parametrize("change", ["organization", "partial_owner", "github", "branch", "subscription"])
def test_start_rejects_mismatched_release_scope(tmp_path, change):
    app, old_id, new_id = releases(tmp_path)
    if change == "organization":
        app.jobs[old_id]["organization_id"] = "team_b"
    elif change == "partial_owner":
        app.jobs[old_id].pop("created_by")
    else:
        source = {
            "repository_url": "https://github.com/team/demo",
            "branch": "main",
            "subscription_id": "f" * 16,
            "organization_id": "team_a",
            "created_by": "creator",
        }
        app.jobs[old_id]["github_source"] = dict(source)
        if change != "github":
            app.jobs[new_id]["github_source"] = dict(source)
            app.jobs[new_id]["github_source"]["branch" if change == "branch" else "subscription_id"] = (
                "different"
            )
    with patch("interfaces.http.server.threading.Thread") as thread, pytest.raises(ValueError):
        app.start_release_rollback(new_id)
    thread.assert_not_called()
    assert app.jobs[new_id].get("release_rollback_state") is None
    assert app.jobs[old_id]["deployment_state"] == "superseded"


def test_manual_releases_from_same_organization_allow_collaboration(tmp_path):
    app, old_id, new_id = releases(tmp_path)
    app.jobs[old_id]["created_by"] = "other_creator"
    with patch("interfaces.http.server.threading.Thread") as thread:
        app.start_release_rollback(new_id)
    thread.assert_called_once()
    assert app.jobs[new_id]["release_rollback_state"] == "running"


def test_changed_owner_after_acceptance_never_reaches_aws(tmp_path):
    app, old_id, new_id = releases(tmp_path)
    with patch("interfaces.http.server.threading.Thread"):
        app.start_release_rollback(new_id)
    app.jobs[old_id]["organization_id"] = "team_b"
    with patch("interfaces.http.server.AwsExpressAdapter") as adapter:
        app.run_release_rollback(new_id)
    adapter.assert_not_called()
    assert app.jobs[new_id]["release_rollback_state"] == "failed"
    assert app.jobs[new_id]["deployment_state"] == "active"
    assert app.jobs[old_id]["deployment_state"] == "superseded"


def test_reconcile_checks_scope_before_aws_queries(tmp_path):
    app, old_id, new_id = releases(tmp_path)
    app.jobs[new_id].update(
        release_rollback_state="needs_attention",
        release_rollback_target_id=old_id,
        release_rollback_submitted=True,
        deployment_state="needs_attention",
    )
    app.jobs[old_id]["organization_id"] = "team_b"
    with patch("interfaces.http.server.AwsExpressAdapter") as adapter, pytest.raises(ValueError):
        app.reconcile_release_rollback(new_id)
    adapter.assert_not_called()


def test_changed_owner_during_aws_call_does_not_publish_rollback_success(tmp_path):
    app, old_id, new_id = releases(tmp_path)
    with patch("interfaces.http.server.threading.Thread"):
        app.start_release_rollback(new_id)

    def submitted_then_changed(*args):
        checkpoint = args[-1]
        checkpoint(release_rollback_submitted=True)
        app.jobs[old_id]["organization_id"] = "team_b"
        return {"state": "successful"}

    with patch("interfaces.http.server.AwsExpressAdapter") as adapter:
        adapter.return_value.rollback_release.side_effect = submitted_then_changed
        app.run_release_rollback(new_id)
    assert app.jobs[new_id]["release_rollback_state"] == "needs_attention"
    assert app.jobs[new_id]["deployment_state"] == "needs_attention"
    assert app.jobs[old_id]["deployment_state"] == "superseded"


def test_same_github_subscription_allows_rollback_across_commits(tmp_path):
    app, old_id, new_id = releases(tmp_path)
    source = {
        "repository_url": "https://github.com/team/demo",
        "branch": "main",
        "subscription_id": "f" * 16,
        "organization_id": "team_a",
        "created_by": "creator",
    }
    app.jobs[old_id]["github_source"] = {**source, "commit": "a" * 40}
    app.jobs[new_id]["github_source"] = {**source, "commit": "b" * 40}
    with patch("interfaces.http.server.threading.Thread") as thread:
        app.start_release_rollback(new_id)
    thread.assert_called_once()
    assert app.jobs[new_id]["release_rollback_target_id"] == old_id


def test_http_accepts_authorized_previous_release(tmp_path):
    app, old_id, new_id = releases(tmp_path)
    principal = Principal("operator", "team_a", Role.DEPLOYER, LoginSource.EXTERNAL_IDP)
    body = json.dumps({"target_job_id": old_id}).encode()
    with patch.object(app, "start_release_rollback") as worker:
        status, _ = _handler(app, principal, f"/api/jobs/{new_id}/rollback-release", method="POST", body=body)
    assert status == 202
    worker.assert_called_once_with(new_id, old_id)
