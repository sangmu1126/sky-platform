"""GitHub execution admission must retain the accepted source and ownership scope."""

from unittest.mock import patch

import pytest

from domain.access import LoginSource, Principal, ResourceOwner, Role
from tests.regression.test_http_ownership import _handler
from tests.unit.test_github_public_url import FIRST, SECOND, archive
from tests.unit.test_github_retry_integrity import make_app


def create_pending(app):
    with (
        patch("application.github_deployments.resolve_revision", return_value=("main", FIRST)),
        patch("application.github_deployments.download_revision", side_effect=archive),
        patch.object(app, "start_job_worker"),
    ):
        created = app.create_github_deployment(
            "https://github.com/team/demo",
            None,
            "demo-app",
            ["local-docker"],
            False,
            True,
            owner=ResourceOwner("team_a", "creator"),
        )
    return created["source_id"], created["deployment"]["id"]


@pytest.mark.parametrize("static", [False, True])
@pytest.mark.parametrize(
    "field,value",
    [
        ("organization_id", "team_b"),
        ("created_by", "other_creator"),
        ("organization_id", None),
        ("repository_url", "https://github.com/other/demo"),
        ("branch", "different"),
        ("application_id", "other-app"),
        ("last_revision", SECOND),
        ("last_job_ids", ["f" * 16]),
    ],
)
def test_changed_connection_is_blocked_before_adapter_or_model(tmp_path, static, field, value):
    app = make_app(tmp_path)
    source_id, job_id = create_pending(app)
    app.github_sources[source_id][field] = value
    with (
        patch("interfaces.http.server.DeploymentAgent") as agent,
        patch.object(app, "static_adapter") as adapter,
    ):
        (app.run_static_site if static else app.run_agent)(job_id)
    agent.assert_not_called()
    adapter.assert_not_called()
    assert app.jobs[job_id]["status"] == "interrupted"
    assert app.jobs[job_id]["github_dispatch_blocked"] is True
    assert not app.jobs[job_id].get("github_dispatch_admitted")


def test_unchanged_owned_connection_is_admitted(tmp_path):
    app = make_app(tmp_path)
    source_id, job_id = create_pending(app)
    with app.lock:
        assert app._admit_github_job_locked(job_id)
    assert app.jobs[job_id]["github_dispatch_admitted"] is True
    assert app.github_sources[source_id]["created_by"] == "creator"


@pytest.mark.parametrize("operation", ["pause", "resume", "check", "retry", "disconnect"])
@pytest.mark.parametrize(
    "organization,role,expected",
    [
        ("team_b", Role.ADMIN, 404),
        ("team_a", Role.VIEWER, 403),
        ("team_a", Role.DEPLOYER, 200),
        ("team_a", Role.ADMIN, 200),
    ],
)
def test_source_route_authorization_runs_before_mutation(tmp_path, operation, organization, role, expected):
    app = make_app(tmp_path)
    source_id, _ = create_pending(app)
    principal = Principal("operator", organization, role, LoginSource.EXTERNAL_IDP)
    if operation == "disconnect" and role is Role.DEPLOYER:
        expected = 403
    with (
        patch.object(app, "set_github_source_enabled", return_value={}) as toggle,
        patch.object(app, "poll_github_source", return_value={}) as poll,
        patch.object(app, "remove_github_source", return_value={}) as remove,
    ):
        status, _ = _handler(app, principal, f"/api/github/sources/{source_id}/{operation}", method="POST")
    assert status == (202 if operation == "retry" and expected == 200 else expected)
    assert toggle.call_count + poll.call_count + remove.call_count == (1 if expected == 200 else 0)


def test_failed_admission_save_does_not_bypass_later_scope_check(tmp_path):
    app = make_app(tmp_path)
    source_id, job_id = create_pending(app)
    with (
        patch.object(app, "save", side_effect=OSError("disk unavailable")),
        app.lock,
        pytest.raises(OSError),
    ):
        app._admit_github_job_locked(job_id)
    assert not app.jobs[job_id].get("github_dispatch_admitted")
    app.github_sources[source_id]["organization_id"] = "team_b"
    with app.lock:
        assert not app._admit_github_job_locked(job_id)
    assert app.jobs[job_id]["github_dispatch_blocked"] is True
