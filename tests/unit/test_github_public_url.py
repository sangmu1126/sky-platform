"""GitHub imports preserve public URL intent through restart, push and retry."""

import io
import json
import zipfile
from unittest.mock import Mock, patch

import pytest

from adapters.aws.ecs import AwsSettings
from application.analysis import AISettings
from application.deployment_core import source_digest
from interfaces.http.server import App, handler_for

FIRST = "a" * 40
SECOND = "b" * 40


def archive(repository, commit, destination):
    with zipfile.ZipFile(destination, "w") as bundle:
        bundle.writestr("package.json", '{"scripts":{"start":"node server.js"}}')
        bundle.writestr("server.js", "require('http').createServer((q,s)=>s.end('ok')).listen(8080);")


def test_subscription_restores_public_requirement_and_reuses_it_for_push_and_retry(tmp_path):
    observed = []

    class Planner:
        def __init__(self, settings):
            pass

        def propose(self, files, targets, public, *, public_url_required=False):
            observed.append((set(targets), public, public_url_required))
            return {
                "target": "aws-ecs-express",
                "workload": "stateless-http",
                "rationale": "공개 URL 필수",
                "evidence": [{"file": "server.js", "quote": "createServer"}],
            }

    def app():
        return App(
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
                ("main", SECOND),
            ],
        ),
        patch("application.github_deployments.download_revision", side_effect=archive),
        patch("interfaces.http.server.AwsSettings.unavailable_reason", return_value=None),
        patch("interfaces.http.server.CloudRunSettings.unavailable_reason", return_value=None),
    ):
        original = app()
        with patch.object(original, "start_job_worker", return_value=True):
            created = original.create_github_deployment(
                "https://github.com/team/demo",
                None,
                "demo-app",
                ["auto"],
                True,
                True,
                public_url_required=True,
            )
        source_id = created["source_id"]
        original.jobs[created["deployment"]["id"]]["status"] = "failed"
        original.save(created["deployment"]["id"])
        restored = app()
        assert restored.github_sources[source_id]["public_url_required"] is True
        with patch.object(restored, "start_job_worker", return_value=True):
            updated = restored.poll_github_source(source_id)
            assert updated["changed"] is True
            job = restored.jobs[updated["job_ids"][0]]
            assert job["deployment_policy"]["public_url_required"] is True
            assert job["infrastructure_plan"]["selection_conditions"]["public_url_required"] is True
            job["status"] = "failed"
            restored.save(job["id"])
            retry = restored.poll_github_source(source_id, retry_failed=True)
            assert retry["changed"] is True
            assert restored.jobs[retry["job_ids"][0]]["deployment_policy"]["public_url_required"] is True
        assert observed == [({"aws-ecs-express", "cloud-run"}, True, True)] * 3


def test_public_requirement_has_no_local_fallback_when_cloud_configuration_disappears(tmp_path):
    app = App(tmp_path, AISettings("fixture-key", "fixture-model"), monitor_interval=0)
    with (
        patch("application.github_deployments.resolve_revision", return_value=("main", FIRST)),
        patch("application.github_deployments.download_revision", side_effect=archive),
        patch.object(app, "infrastructure_planner_factory") as planner,
        patch("interfaces.http.server.AwsSettings.unavailable_reason", return_value="not configured"),
        patch("interfaces.http.server.CloudRunSettings.unavailable_reason", return_value="not configured"),
        pytest.raises(ValueError, match="자동 배포 대상이 없습니다"),
    ):
        app.create_github_deployment(
            "https://github.com/team/demo",
            None,
            "demo-app",
            ["auto"],
            True,
            False,
            public_url_required=True,
        )
    planner.assert_not_called()
    assert not app.jobs


@pytest.mark.parametrize(
    "targets,public,required",
    [
        (["auto"], False, True),
        (["local-docker"], True, True),
        (["local-docker", "aws-ecs-express"], True, True),
        (["auto"], True, "true"),
    ],
)
def test_inconsistent_conditions_are_rejected_before_github_network(tmp_path, targets, public, required):
    app = App(tmp_path, AISettings("fixture-key", "fixture-model"), monitor_interval=0)
    with (
        patch("application.github_deployments.resolve_revision") as resolve,
        pytest.raises(ValueError, match="공개 URL 필수"),
    ):
        app.create_github_deployment(
            "https://github.com/team/demo",
            None,
            "demo-app",
            targets,
            public,
            False,
            public_url_required=required,
        )
    resolve.assert_not_called()


def test_github_http_endpoint_accepts_optional_public_requirement(tmp_path):
    app = App(tmp_path, AISettings("fixture-key", "fixture-model"), monitor_interval=0)
    body = json.dumps(
        {
            "repository_url": "https://github.com/team/demo",
            "branch": None,
            "application_id": "demo-app",
            "targets": ["auto"],
            "public": True,
            "auto_deploy": False,
            "public_url_required": True,
        }
    ).encode()
    handler = handler_for(app).__new__(handler_for(app))
    handler.path = "/api/github/deployments"
    handler.headers = {"X-Sky-Token": app.token, "Content-Length": str(len(body))}
    handler.rfile = io.BytesIO(body)
    handler.json_response = Mock()
    with patch.object(app, "create_github_deployment", return_value={"deployment": {}}) as create:
        handler.do_POST()
    assert handler.json_response.call_args.args[0] == 202
    assert create.call_args.kwargs["public_url_required"] is True


def test_static_github_route_keeps_public_requirement(tmp_path):
    app = App(
        tmp_path,
        AISettings("fixture-key", "fixture-model"),
        monitor_interval=0,
        aws_settings=AwsSettings("ap-northeast-2", expected_account="123456789012"),
    )

    def static_archive(repository, commit, destination):
        with zipfile.ZipFile(destination, "w") as bundle:
            bundle.writestr("index.html", "<h1>Hello</h1>")

    with (
        patch("application.github_deployments.resolve_revision", return_value=("main", FIRST)),
        patch("application.github_deployments.download_revision", side_effect=static_archive),
        patch("application.github_deployments.AwsStaticSiteAdapter.unavailable_reason", return_value=None),
        patch(
            "application.static_deployments.AwsStaticSiteAdapter.preflight",
            side_effect=lambda project, *args: {"source_digest": source_digest(project)},
        ),
        patch.object(app, "start_job_worker", return_value=True),
    ):
        result = app.create_github_deployment(
            "https://github.com/team/demo", None, "demo-app", ["auto"], True, False, public_url_required=True
        )
    job = app.jobs[result["deployment"]["id"]]
    assert job["target"] == "aws-s3-cloudfront"
    assert job["deployment_policy"]["public_url_required"] is True


@pytest.mark.parametrize(
    "required,public,targets",
    [
        ("true", True, ["auto"]),
        (True, False, ["auto"]),
        (True, True, ["local-docker"]),
    ],
)
def test_invalid_persisted_conditions_disable_subscription(tmp_path, required, public, targets):
    app = App(tmp_path, AISettings("fixture-key", "fixture-model"), monitor_interval=0)
    record = {
        "id": "c" * 16,
        "repository_url": "https://github.com/team/demo",
        "branch": "main",
        "application_id": "demo-app",
        "targets": targets,
        "public": public,
        "enabled": True,
        "last_revision": FIRST,
        "last_job_ids": ["d" * 16],
        "public_url_required": required,
    }
    with patch.object(app.record_store, "load_github_sources", return_value=[record]):
        app.restore_github_sources()
    assert not app.github_sources
    assert any("GitHub" in warning for warning in app.recovery_warnings)
