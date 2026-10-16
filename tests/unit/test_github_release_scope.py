"""Deployment permission does not imply permission to adopt an unrelated release."""

from copy import deepcopy
from unittest.mock import patch

import pytest

from adapters.aws.ecs import AwsSettings
from application.analysis import AISettings
from engine.github_release_scope import same_github_release_scope
from interfaces.http.server import App

OWNER = {"organization_id": "team_a", "created_by": "user_1"}


def source():
    return {
        "repository_url": "https://github.com/team/demo",
        "branch": "main",
        "subscription_id": "a" * 16,
        **OWNER,
    }


def release(job_id="b" * 16, target="aws-ecs-express"):
    return {
        "id": job_id,
        "application_id": "demo-app",
        "target": target,
        "status": "succeeded",
        "deployment_state": "active",
        "created_at": "2026-10-16T01:00:00Z",
        "github_source": source(),
        "result": {"service": "old-service"},
        **OWNER,
    }


def test_matching_lineage_and_legacy_local_records():
    old, new = release(), release("c" * 16)
    assert same_github_release_scope(old, new)
    for record in (old, new):
        for key in OWNER:
            record.pop(key)
            record["github_source"].pop(key)
    assert same_github_release_scope(old, new)
    old.pop("github_source")
    assert not same_github_release_scope(old, new)


@pytest.mark.parametrize(
    "section,field,value",
    [
        ("github_source", "repository_url", "https://github.com/other/demo"),
        ("github_source", "branch", "other"),
        ("github_source", "subscription_id", "d" * 16),
        ("github_source", "subscription_id", ""),
        ("github_source", "created_by", "user_2"),
        ("github_source", "organization_id", "team_b"),
        (None, "organization_id", "team_b"),
        (None, "created_by", "user_2"),
        (None, "application_id", "other-app"),
        (None, "application_id", None),
    ],
)
def test_mixed_or_unrelated_scope_never_matches(section, field, value):
    old, new = release(), release("c" * 16)
    (new[section] if section else new)[field] = value
    assert not same_github_release_scope(old, new)


def app_and_project(tmp_path):
    app = App(
        tmp_path,
        AISettings("fixture-key", "fixture-model"),
        monitor_interval=0,
        aws_settings=AwsSettings("ap-northeast-2", expected_account="123456789012"),
    )
    project = tmp_path / "input"
    project.mkdir()
    (project / "server.js").write_text("require('http').createServer((q,s)=>s.end('ok')).listen(8080);")
    (project / "package.json").write_text('{"scripts":{"start":"node server.js"}}')
    return app, project


def test_aws_adopts_matching_release_instead_of_newest_unrelated_release(tmp_path):
    app, project = app_and_project(tmp_path)
    matching, unrelated = release(), release("c" * 16)
    unrelated["github_source"]["subscription_id"] = "d" * 16
    unrelated["created_at"] = "2026-10-16T02:00:00Z"
    app.jobs = {matching["id"]: matching, unrelated["id"]: unrelated}
    result = app._reserve_single_github_job(project, "demo-app", "aws-ecs-express", True, source())
    assert app.jobs[result["id"]]["replaces_job_id"] == matching["id"]
    assert unrelated["deployment_state"] == "active"


def test_aws_never_adopts_existing_zip_release(tmp_path):
    app, project = app_and_project(tmp_path)
    old = release()
    old.pop("github_source")
    app.jobs = {old["id"]: old}
    with pytest.raises(ValueError, match="수동 확인"):
        app._reserve_single_github_job(project, "demo-app", "aws-ecs-express", True, source())
    assert set(app.jobs) == {old["id"]}
    assert old["deployment_state"] == "active"


def test_local_cleanup_rechecks_recorded_lineage_before_retiring_container(tmp_path):
    app, _project = app_and_project(tmp_path)
    old, new = release(target="local-docker"), release("c" * 16, "local-docker")
    new["git_replaces_local_job_id"] = old["id"]
    new["github_source"]["branch"] = "other"
    new["events"] = []
    app.jobs = {old["id"]: old, new["id"]: new}
    before = deepcopy(old)
    (tmp_path / new["id"]).mkdir()
    with patch("application.github_deployments.LocalDockerAdapter") as docker:
        app.retire_replaced_github_local(new["id"])
    docker.assert_not_called()
    assert old == before
    assert new["events"][-1]["stage"] == "previous_local_cleanup_blocked"


def test_static_replacement_rejects_conflicting_owner_even_with_same_subscription(tmp_path):
    app, project = app_and_project(tmp_path)
    (project / "server.js").unlink()
    (project / "package.json").unlink()
    (project / "index.html").write_text("<h1>Hello</h1>")
    old = release(target="aws-s3-cloudfront")
    old.update(static_stack_id="old-stack", organization_id="team_b")
    app.jobs = {old["id"]: old}
    from application.deployment_core import source_digest
    from domain.access import ResourceOwner

    with (
        patch(
            "application.static_deployments.AwsStaticSiteAdapter.preflight",
            return_value={"source_digest": source_digest(project)},
        ),
        pytest.raises(ValueError, match="기존 정적 사이트"),
    ):
        app.create_static_job(
            "c" * 16,
            project,
            "demo-app",
            requested_target="auto",
            source=source(),
            owner=ResourceOwner(**OWNER),
        )
    assert set(app.jobs) == {old["id"]}


def test_one_shot_git_import_does_not_adopt_watched_subscription():
    old, new = release(), release("c" * 16)
    new["github_source"]["subscription_id"] = None
    assert not same_github_release_scope(old, new)
    old["github_source"]["subscription_id"] = None
    assert same_github_release_scope(old, new)


@pytest.mark.parametrize("index", range(4))
def test_partial_owner_records_cannot_match(index):
    old, new = release(), release("c" * 16)
    (old, old["github_source"], new, new["github_source"])[index].pop("created_by")
    assert not same_github_release_scope(old, new)
