"""Installed provider and operator pins are both required for hosted execution."""

import json
from pathlib import PurePosixPath
from unittest.mock import Mock, patch

import pytest

from application.environment_execution_composition import (
    RegisteredEnvironmentEffectRouter,
    RegisteredEnvironmentExecutionComposition,
    RegisteredEnvironmentResourceRouter,
)
from interfaces.b_runtime import main
from interfaces.environment_execution_provider import main as inspect_provider
from interfaces.environment_execution_registration import (
    ENTRY_POINT_GROUP,
    EnvironmentProviderArtifact,
    attest_environment_execution_provider,
    compose_environment_executions,
    environment_execution_entry_points,
    load_environment_execution_manifest,
)
from tests.unit.test_environment_admission import registered


def composition():
    execution = registered()
    return RegisteredEnvironmentExecutionComposition(
        execution,
        "EVR-" + "a" * 64,
        Mock(verify=Mock(return_value={"verified": True})),
        "EEF-" + "b" * 64,
        Mock(return_value={"result_ref": "result"}),
    )


def manifest_file(tmp_path, selected, entry_point=None, **changes):
    artifact = (
        attest_environment_execution_provider(entry_point)
        if entry_point is not None
        else EnvironmentProviderArtifact("installed-provider", "sky-environment-provider", "1.2.3", "c" * 64)
    )
    value = {
        "schema_version": 2,
        "profile": "reviewed_environment_execution_worker_v2",
        "workspace": "test",
        **artifact.document(),
        "registrations": [
            {
                "registration_id": selected.execution.job.id,
                "execution_revision": selected.execution.revision,
                "application_id": selected.execution.job.transfer.source.application_id,
                "resource_verifier_ref": selected.resource_verifier_ref,
                "effect_ref": selected.effect_ref,
            }
        ],
    }
    value.update(changes)
    path = tmp_path / "environment-worker.json"
    path.write_text(json.dumps(value))
    return path


class Distribution:
    def __init__(self, root, source="def provide(selected): return ()\n"):
        self.root = root
        self.metadata = {"Name": "sky-environment-provider"}
        self.version = "1.2.3"
        documents = {
            "sky_env_provider.py": source,
            "sky_environment_provider-1.2.3.dist-info/METADATA": (
                "Name: sky-environment-provider\nVersion: 1.2.3\n"
            ),
            "sky_environment_provider-1.2.3.dist-info/entry_points.txt": (
                "[sky.environment_execution.v1]\ninstalled-provider=sky_env_provider:provide\n"
            ),
        }
        for name, content in documents.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            path.chmod(0o644)
        self.files = tuple(PurePosixPath(value) for value in documents)

    def locate_file(self, value):
        return self.root / str(value)


class EntryPoint:
    group = ENTRY_POINT_GROUP
    name = "installed-provider"
    value = "sky_env_provider:provide"

    def __init__(self, provider, root):
        self.provider = provider
        self.loads = 0
        self.dist = Distribution(root)
        self.module_path = root / "sky_env_provider.py"

    def load(self):
        self.loads += 1
        return self.provider


def test_operator_manifest_and_installed_provider_must_match_exactly(tmp_path):
    selected = composition()
    provider = Mock(return_value=(selected,))
    entry_point = EntryPoint(provider, tmp_path / "provider")
    manifest = load_environment_execution_manifest(
        manifest_file(tmp_path, selected, entry_point), workspace="test"
    )

    assert compose_environment_executions(manifest, entry_points=[entry_point]) == (selected,)
    provider.assert_called_once_with((selected.execution.job.id,))
    assert entry_point.loads == 1

    changed = RegisteredEnvironmentExecutionComposition(
        selected.execution,
        "EVR-" + "c" * 64,
        selected.resource_verifier,
        selected.effect_ref,
        selected.effect,
    )
    changed_entry_point = EntryPoint(lambda _selected: (changed,), tmp_path / "changed-provider")
    with pytest.raises(ValueError, match="differs from operator pins"):
        compose_environment_executions(
            load_environment_execution_manifest(
                manifest_file(tmp_path, selected, changed_entry_point), workspace="test"
            ),
            entry_points=[changed_entry_point],
        )


def test_composition_routers_never_select_from_queue_data():
    selected = composition()
    guard, journal = Mock(), Mock()
    resources = RegisteredEnvironmentResourceRouter((selected,))
    effects = RegisteredEnvironmentEffectRouter((selected,))

    resources.verify(selected.execution, guard=guard)
    effects(selected.execution, guard=guard, journal=journal)
    selected.resource_verifier.verify.assert_called_once_with(selected.execution, guard=guard)
    selected.effect.assert_called_once_with(selected.execution, guard=guard, journal=journal)

    other = registered()
    object.__setattr__(other.job, "id", "other-registration")
    with pytest.raises(ValueError, match="registration changed"):
        effects(other, guard=guard, journal=journal)


@pytest.mark.parametrize(
    "change",
    [
        {"workspace": "other"},
        {"provider": "module.path"},
        {"registrations": []},
        {"extra": True},
    ],
)
def test_manifest_rejects_wrong_scope_unknown_fields_and_empty_authority(tmp_path, change):
    selected = composition()
    with pytest.raises(ValueError):
        load_environment_execution_manifest(manifest_file(tmp_path, selected, **change), workspace="test")


def test_provider_discovery_requires_one_installed_entry_point(tmp_path):
    with pytest.raises(ValueError, match="Exactly one"):
        environment_execution_entry_points("installed-provider", entry_points=[])
    duplicate = [
        EntryPoint(Mock(), tmp_path / "provider-one"),
        EntryPoint(Mock(), tmp_path / "provider-two"),
    ]
    with pytest.raises(ValueError, match="Exactly one"):
        environment_execution_entry_points("installed-provider", entry_points=duplicate)


def test_cli_check_config_does_not_import_provider_or_call_aws_or_database(tmp_path, monkeypatch, capsys):
    selected = composition()
    entry_point = EntryPoint(Mock(side_effect=AssertionError("provider called")), tmp_path / "provider")
    path = manifest_file(tmp_path, selected, entry_point)
    ca = tmp_path / "ca.pem"
    ca.write_text("configuration-only")
    values = {
        "SKY_DATABASE_HOST": "db.example",
        "SKY_DATABASE_NAME": "sky",
        "SKY_DATABASE_SECRET_ARN": "arn:aws:secretsmanager:ap-northeast-2:977889523182:secret:test",
        "SKY_DATABASE_SSLROOTCERT": str(ca),
        "SKY_AWS_REGION": "ap-northeast-2",
        "SKY_AWS_ACCOUNT_ID": "977889523182",
        "SKY_STATE_WORKSPACE": "test",
        "SKY_JOB_QUEUE_URL": "https://sqs.ap-northeast-2.amazonaws.com/977889523182/jobs.fifo",
        "SKY_ENVIRONMENT_EXECUTION_QUEUE_URL": "https://sqs.ap-northeast-2.amazonaws.com/977889523182/environment.fifo",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    with (
        patch(
            "interfaces.environment_execution_registration.metadata.entry_points",
            return_value=[entry_point],
        ),
        patch("interfaces.shared_database_worker.load_hosted_identity", return_value=Mock()),
        patch("boto3.client", side_effect=AssertionError("AWS called")),
        patch(
            "adapters.state.postgres.RotatingDatabaseConnection",
            side_effect=AssertionError("DB called"),
        ),
    ):
        main(
            [
                "worker",
                "--mode",
                "environment-execution",
                "--environment-execution-config",
                str(path),
                "--check-config",
            ]
        )
    assert entry_point.loads == 0
    assert "provider code, AWS and DB were not called" in capsys.readouterr().out


def test_cli_composes_only_pinned_provider_and_runs_one_hosted_delivery(tmp_path, monkeypatch, capsys):
    selected = composition()
    entry_point = EntryPoint(Mock(return_value=(selected,)), tmp_path / "provider")
    path = manifest_file(tmp_path, selected, entry_point)
    ca = tmp_path / "ca.pem"
    ca.write_text("runtime-test")
    for name, value in {
        "SKY_DATABASE_HOST": "db.example",
        "SKY_DATABASE_NAME": "sky",
        "SKY_DATABASE_SECRET_ARN": "arn:aws:secretsmanager:ap-northeast-2:977889523182:secret:test",
        "SKY_DATABASE_SSLROOTCERT": str(ca),
        "SKY_AWS_REGION": "ap-northeast-2",
        "SKY_AWS_ACCOUNT_ID": "977889523182",
        "SKY_STATE_WORKSPACE": "test",
        "SKY_JOB_QUEUE_URL": "https://sqs.ap-northeast-2.amazonaws.com/977889523182/jobs.fifo",
        "SKY_ENVIRONMENT_EXECUTION_QUEUE_URL": "https://sqs.ap-northeast-2.amazonaws.com/977889523182/environment.fifo",
    }.items():
        monkeypatch.setenv(name, value)
    store = Mock(workspace="test")
    queue = Mock()
    admission = Mock()

    with (
        patch(
            "interfaces.environment_execution_registration.metadata.entry_points",
            return_value=[entry_point],
        ),
        patch("interfaces.shared_database_worker.load_hosted_identity", return_value=Mock()),
        patch("adapters.aws.job_queue.SqsOperationQueue", return_value=queue),
        patch("adapters.state.operations.PostgresOperationStore", return_value=store),
        patch("adapters.state.postgres.RotatingDatabaseConnection") as connection,
        patch("adapters.state.readiness.check_database_ready") as ready,
        patch("adapters.state.deployment_admission.PostgresDeploymentAdmission"),
        patch(
            "adapters.state.environment_admission.PostgresEnvironmentExecutionAdmission",
            return_value=admission,
        ),
        patch(
            "interfaces.environment_execution_consumer.run_reviewed_environment_consumer",
            return_value="idle",
        ) as run,
    ):
        main(
            [
                "worker",
                "--mode",
                "environment-execution",
                "--environment-execution-config",
                str(path),
                "--once",
            ]
        )

    assert entry_point.loads == 1
    entry_point.provider.assert_called_once_with((selected.execution.job.id,))
    ready.assert_called_once_with(connection.return_value, operations=True)
    admission.check_ready.assert_called_once_with()
    run.assert_called_once()
    assert run.call_args.kwargs == {"once": True, "wait_seconds": 5}
    assert "Reviewed environment consumer: idle" in capsys.readouterr().out


def test_provider_artifact_is_verified_before_and_after_import(tmp_path):
    selected = composition()
    entry_point = EntryPoint(Mock(return_value=(selected,)), tmp_path / "provider")
    manifest = load_environment_execution_manifest(
        manifest_file(tmp_path, selected, entry_point), workspace="test"
    )
    entry_point.module_path.write_text("changed before import\n")
    with pytest.raises(ValueError, match="differs from operator pin"):
        compose_environment_executions(manifest, entry_points=[entry_point])
    assert entry_point.loads == 0

    after = EntryPoint(Mock(), tmp_path / "after-provider")

    def change_after_import(_selected):
        after.module_path.write_text("changed during provider load\n")
        return (selected,)

    after.provider.side_effect = change_after_import
    manifest = load_environment_execution_manifest(manifest_file(tmp_path, selected, after), workspace="test")
    with pytest.raises(ValueError, match="differs from operator pin"):
        compose_environment_executions(manifest, entry_points=[after])


def test_provider_artifact_rejects_writable_or_unbounded_package(tmp_path):
    entry_point = EntryPoint(Mock(), tmp_path / "provider")
    entry_point.module_path.chmod(0o666)
    with pytest.raises(ValueError, match="Immutable bounded"):
        attest_environment_execution_provider(entry_point)
    entry_point.module_path.chmod(0o644)
    entry_point.dist.files = (*entry_point.dist.files, PurePosixPath("../outside.py"))
    with pytest.raises(ValueError, match="Canonical provider distribution path"):
        attest_environment_execution_provider(entry_point)


def test_provider_inspection_prints_approval_pin_without_import(tmp_path, capsys):
    entry_point = EntryPoint(Mock(side_effect=AssertionError("provider imported")), tmp_path / "provider")
    expected = attest_environment_execution_provider(entry_point)
    with patch(
        "interfaces.environment_execution_registration.metadata.entry_points",
        return_value=[entry_point],
    ):
        inspect_provider(["--provider", "installed-provider"])
    assert entry_point.loads == 0
    assert json.loads(capsys.readouterr().out) == {
        "schema_version": 1,
        "profile": "reviewed_environment_provider_artifact_v1",
        **expected.document(),
    }


@pytest.mark.parametrize("mode", ["outbox", "operating-review", "dedicated-database"])
def test_environment_manifest_cannot_activate_another_worker_mode(tmp_path, mode):
    selected = composition()
    with pytest.raises(SystemExit) as error:
        main(
            [
                "worker",
                "--mode",
                mode,
                "--environment-execution-config",
                str(manifest_file(tmp_path, selected)),
                "--check-config",
            ]
        )
    assert error.value.code == 2
