"""A same-commit retry must preserve source identity and subscription intent."""

import hashlib
import zipfile
from unittest.mock import patch

import pytest

from application.analysis import AISettings
from interfaces.http.server import App
from tests.unit.test_github_public_url import FIRST, SECOND, archive


def make_app(tmp_path):
    return App(
        tmp_path, AISettings("fixture-key", "fixture-model"), monitor_interval=0, github_poll_interval=60
    )


def create_failed(app):
    created = app.create_github_deployment(
        "https://github.com/team/demo", None, "demo-app", ["local-docker"], False, True
    )
    job_id = created["deployment"]["id"]
    app.jobs[job_id]["status"] = "failed"
    app.save(job_id)
    return created["source_id"], job_id


def test_same_commit_with_changed_source_is_rejected_before_reservation(tmp_path):
    app = make_app(tmp_path)
    calls = 0

    def download(repository, commit, destination):
        nonlocal calls
        calls += 1
        archive(repository, commit, destination)
        if calls == 2:
            with zipfile.ZipFile(destination, "a") as bundle:
                bundle.writestr("extra.txt", "changed source")

    with (
        patch("application.github_deployments.resolve_revision", return_value=("main", FIRST)),
        patch("application.github_deployments.download_revision", side_effect=download),
        patch.object(app, "start_job_worker", return_value=True) as worker,
    ):
        source_id, job_id = create_failed(app)
        with pytest.raises(ValueError, match="동일 커밋의 소스"):
            app.poll_github_source(source_id, retry_failed=True)
    assert set(app.jobs) == {job_id}
    assert app.github_sources[source_id]["last_job_ids"] == [job_id]
    assert worker.call_count == 1


def test_same_source_with_different_zip_metadata_remains_retryable(tmp_path):
    app = make_app(tmp_path)
    archives = []

    def download(repository, commit, destination):
        archive(repository, commit, destination)
        with zipfile.ZipFile(destination, "a") as bundle:
            bundle.comment = f"archive metadata {len(archives)}".encode()
        archives.append(hashlib.sha256(destination.read_bytes()).hexdigest())

    with (
        patch("application.github_deployments.resolve_revision", return_value=("main", FIRST)),
        patch("application.github_deployments.download_revision", side_effect=download),
        patch.object(app, "start_job_worker", return_value=True),
    ):
        source_id, old_id = create_failed(app)
        changed = app.poll_github_source(source_id, retry_failed=True)
    new_id = changed["job_ids"][0]
    assert new_id != old_id
    assert archives[0] != archives[1]
    assert app.jobs[new_id]["source_digest"] == app.jobs[old_id]["source_digest"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_digest", None),
        ("source_digest", "invalid"),
        ("commit", SECOND),
        ("subscription_id", "f" * 16),
    ],
)
def test_retry_requires_previous_source_identity_before_downloading(tmp_path, field, value):
    app = make_app(tmp_path)
    with (
        patch("application.github_deployments.resolve_revision", return_value=("main", FIRST)),
        patch("application.github_deployments.download_revision", side_effect=archive) as download,
        patch.object(app, "start_job_worker", return_value=True),
    ):
        source_id, job_id = create_failed(app)
        record = app.jobs[job_id] if field == "source_digest" else app.jobs[job_id]["github_source"]
        record[field] = value
        with pytest.raises(ValueError, match="소스·커밋·소유권"):
            app.poll_github_source(source_id, retry_failed=True)
    assert download.call_count == 1


def test_in_place_subscription_policy_change_discards_unstarted_work(tmp_path):
    app = make_app(tmp_path)
    calls = 0
    source_id = None

    def download(repository, commit, destination):
        nonlocal calls
        calls += 1
        archive(repository, commit, destination)
        if calls == 2:
            app.github_sources[source_id]["targets"].append("cloud-run")

    with (
        patch(
            "application.github_deployments.resolve_revision", side_effect=[("main", FIRST), ("main", SECOND)]
        ),
        patch("application.github_deployments.download_revision", side_effect=download),
        patch.object(app, "start_job_worker", return_value=True) as worker,
    ):
        source_id, old_id = create_failed(app)
        with pytest.raises(ValueError, match="설정이 변경"):
            app.poll_github_source(source_id)
    assert set(app.jobs) == {old_id}
    assert app.github_sources[source_id]["targets"] == ["local-docker", "cloud-run"]
    assert app.github_sources[source_id]["last_revision"] == FIRST
    assert worker.call_count == 1


def test_changed_subscription_pointer_is_not_overwritten_by_failed_poll(tmp_path):
    app = make_app(tmp_path)
    calls = 0
    source_id = None

    def download(repository, commit, destination):
        nonlocal calls
        calls += 1
        archive(repository, commit, destination)
        if calls == 2:
            app.github_sources[source_id].update(last_revision="c" * 40, last_job_ids=["d" * 16])

    with (
        patch(
            "application.github_deployments.resolve_revision", side_effect=[("main", FIRST), ("main", SECOND)]
        ),
        patch("application.github_deployments.download_revision", side_effect=download),
        patch.object(app, "start_job_worker", return_value=True),
    ):
        source_id, old_id = create_failed(app)
        with pytest.raises(ValueError, match="설정이 변경"):
            app.poll_github_source(source_id)
    assert set(app.jobs) == {old_id}
    assert app.github_sources[source_id]["last_revision"] == "c" * 40
    assert app.github_sources[source_id]["last_job_ids"] == ["d" * 16]


def test_changed_subscription_policy_requires_new_request_before_download(tmp_path):
    app = make_app(tmp_path)
    with (
        patch("application.github_deployments.resolve_revision", return_value=("main", FIRST)),
        patch("application.github_deployments.download_revision", side_effect=archive) as download,
        patch.object(app, "start_job_worker", return_value=True),
    ):
        source_id, old_id = create_failed(app)
        app.github_sources[source_id]["public"] = True
        with pytest.raises(ValueError, match="배포 정책이 다릅니다"):
            app.poll_github_source(source_id, retry_failed=True)
    assert download.call_count == 1
    assert set(app.jobs) == {old_id}


def test_subscription_save_failure_rolls_back_only_unpublished_attempt(tmp_path):
    app = make_app(tmp_path)
    with (
        patch(
            "application.github_deployments.resolve_revision", side_effect=[("main", FIRST), ("main", SECOND)]
        ),
        patch("application.github_deployments.download_revision", side_effect=archive),
        patch.object(app, "start_job_worker", return_value=True) as worker,
    ):
        source_id, old_id = create_failed(app)
        save = app.save_github_sources
        calls = 0

        def fail_once():
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("source store unavailable")
            return save()

        with patch.object(app, "save_github_sources", side_effect=fail_once), pytest.raises(OSError):
            app.poll_github_source(source_id)
    assert set(app.jobs) == {old_id}
    assert worker.call_count == 1
    stored = app.record_store.load_github_sources()[0]
    assert stored["last_revision"] == FIRST
    assert stored["last_job_ids"] == [old_id]
