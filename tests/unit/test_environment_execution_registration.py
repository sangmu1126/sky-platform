"""Installed provider and operator pins are both required for hosted execution."""

import json
from unittest.mock import Mock, patch

import pytest

from application.environment_execution_composition import (
    RegisteredEnvironmentEffectRouter,
    RegisteredEnvironmentExecutionComposition,
    RegisteredEnvironmentResourceRouter,
)
from interfaces.b_runtime import main
from interfaces.environment_execution_registration import (
    ENTRY_POINT_GROUP,
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


def manifest_file(tmp_path, selected, **changes):
    value = {
        "schema_version": 1,
        "profile": "reviewed_environment_execution_worker_v1",
        "workspace": "test",
        "provider": "installed-provider",
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


class EntryPoint:
    group = ENTRY_POINT_GROUP
    name = "installed-provider"

    def __init__(self, provider):
        self.provider = provider
        self.loads = 0

    def load(self):
        self.loads += 1
        return self.provider


def test_operator_manifest_and_installed_provider_must_match_exactly(tmp_path):
    selected = composition()
    manifest = load_environment_execution_manifest(manifest_file(tmp_path, selected), workspace="test")
    provider = Mock(return_value=(selected,))
    entry_point = EntryPoint(provider)

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
    with pytest.raises(ValueError, match="differs from operator pins"):
        compose_environment_executions(manifest, entry_points=[EntryPoint(lambda _selected: (changed,))])


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


def test_provider_discovery_requires_one_installed_entry_point():
    with pytest.raises(ValueError, match="Exactly one"):
        environment_execution_entry_points("installed-provider", entry_points=[])
    duplicate = [EntryPoint(Mock()), EntryPoint(Mock())]
    with pytest.raises(ValueError, match="Exactly one"):
        environment_execution_entry_points("installed-provider", entry_points=duplicate)


def test_cli_check_config_does_not_import_provider_or_call_aws_or_database(tmp_path, monkeypatch, capsys):
    selected = composition()
    path = manifest_file(tmp_path, selected)
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
    entry_point = EntryPoint(Mock(side_effect=AssertionError("provider called")))

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
    path = manifest_file(tmp_path, selected)
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
    entry_point = EntryPoint(Mock(return_value=(selected,)))
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
