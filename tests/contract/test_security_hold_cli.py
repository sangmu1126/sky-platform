import json
from unittest.mock import patch

from adapters.state.postgres import PostgresDeploymentRecordStore
from application.security_hold import SecurityHold
from interfaces.b_runtime import main
from tests.contract.test_operation_store import database as database  # noqa: PLC0414
from tests.contract.test_operation_store import store as store  # noqa: PLC0414
from tests.unit.test_deployment_writes import Records
from tests.unit.test_operating_review import ID
from tests.unit.test_security_hold_cli import arguments
from tests.unit.test_security_hold_cli import configured_cli as configured_cli  # noqa: PLC0414

pytest_plugins = ["tests.unit.test_operating_review"]


def test_cli_place_repeat_and_readonly_status_persist_the_same_hold(
    configured_cli, store, database, monkeypatch, capsys
):
    monkeypatch.setenv("SKY_STATE_WORKSPACE", store.workspace)
    records = PostgresDeploymentRecordStore(database, workspace=store.workspace)
    job = Records().job
    job["promotion_automation_consent"] = {"old": True}
    records.save_job(ID, job, expected_revision=None)
    with patch("interfaces.security_hold.RotatingDatabaseConnection", return_value=database):
        main(arguments("place"))
        first = json.loads(capsys.readouterr().out)
        assert first["status"] == "held" and first["observed_only"] is False
        assert records.load_job(ID).record["promotion_automation_consent"] is None
        main(arguments("place"))
        again = json.loads(capsys.readouterr().out)
        assert again["metadata_revision"] == first["metadata_revision"]
        original = SecurityHold.status

        def inspect_readonly(service, *args):
            with service.writer.records.connection_factory() as db:
                assert db.execute("SHOW transaction_read_only").fetchone()[0] == "on"
            return original(service, *args)

        with patch.object(SecurityHold, "status", inspect_readonly):
            main(arguments())
            status = json.loads(capsys.readouterr().out)
        assert status["observed_only"] is True and status["hold"] == first["hold"]
        assert status["metadata_revision"] == first["metadata_revision"]
        assert status["quarantine_performed"] is False and status["credentials_revoked"] is False


def test_cli_observation_persists_fresh_boundary_without_clearing_hold(
    configured_cli, store, database, monkeypatch, capsys, operating_review_setup
):
    from datetime import UTC, datetime

    monkeypatch.setenv("SKY_STATE_WORKSPACE", store.workspace)
    records = PostgresDeploymentRecordStore(database, workspace=store.workspace)
    memory, _, _ = operating_review_setup
    records.save_job(ID, memory.job, expected_revision=None)
    with (
        patch("interfaces.security_hold.RotatingDatabaseConnection", return_value=database),
        patch(
            "interfaces.security_hold.check_deployment",
            side_effect=lambda job: {
                "healthy": True,
                "checked_at": datetime.now(UTC).isoformat(),
                "reason": "HTTP checked",
            },
        ),
    ):
        main(arguments("place"))
        capsys.readouterr()
        held = records.load_job(ID)
        main(arguments("observe"))
        report = json.loads(capsys.readouterr().out)
    assert report["status"] == "held" and report["health_observation"]["healthy"] is True
    assert records.load_job(ID) == held
    observation = records.load_health_record(ID).record[-1]
    assert (
        observation["deployment_binding"]["security_review_boundary"]
        == held.record["security_review_boundary"]
    )
    assert observation["source"] == "manual"


def test_false_positive_release_persists_audit_without_restoring_automation(
    configured_cli, store, database, monkeypatch, capsys, operating_review_setup
):
    from datetime import UTC, datetime

    from tests.unit.test_security_hold_cli import release_arguments

    monkeypatch.setenv("SKY_STATE_WORKSPACE", store.workspace)
    records = PostgresDeploymentRecordStore(database, workspace=store.workspace)
    memory, _, _ = operating_review_setup
    records.save_job(ID, memory.job, expected_revision=None)
    with (
        patch("interfaces.security_hold.RotatingDatabaseConnection", return_value=database),
        patch(
            "interfaces.security_hold.check_deployment",
            side_effect=lambda job: {
                "healthy": True,
                "checked_at": datetime.now(UTC).isoformat(),
                "reason": "HTTP checked",
            },
        ),
    ):
        main(arguments("place"))
        capsys.readouterr()
        main(arguments("observe"))
        held = json.loads(capsys.readouterr().out)
        args = release_arguments(held["metadata_revision"], held["review_boundary"]["id"])
        main(args)
        released = json.loads(capsys.readouterr().out)
        assert released["status"] == "released_false_positive"
        assert released["release"]["review_ref"] == "REVIEW-1"
        assert released["review_boundary"] != held["review_boundary"]
        saved = records.load_job(ID)
        assert saved.record["security_hold"] is None and saved.record["promotion_automation_consent"] is None
        assert len(saved.record["security_hold_history"]) == 1
        main(args)
        again = json.loads(capsys.readouterr().out)
        assert again["metadata_revision"] == released["metadata_revision"]
        assert records.load_job(ID) == saved


def test_runtime_inspection_cli_uses_readonly_state_without_releasing_hold(
    configured_cli, store, database, monkeypatch, capsys
):
    import psycopg
    import pytest

    from tests.unit.test_incident_runtime_inspection import fixture

    monkeypatch.setenv("SKY_STATE_WORKSPACE", store.workspace)
    records = PostgresDeploymentRecordStore(database, workspace=store.workspace)
    job = Records().job
    result, _, _, ecs, sts = fixture()
    job["result"] = result
    records.save_job(ID, job, expected_revision=None)
    original = SecurityHold.status
    observed_readonly = []

    def check_state(service, *args):
        with service.writer.records.connection_factory() as db:
            assert db.execute("SHOW transaction_read_only").fetchone()[0] == "on"
            with pytest.raises(psycopg.errors.ReadOnlySqlTransaction), db.transaction():
                db.execute("UPDATE sky_state.metadata_records SET revision=revision WHERE false")
            observed_readonly.append(True)
        return original(service, *args)

    with patch("interfaces.security_hold.RotatingDatabaseConnection", return_value=database):
        main(arguments("place"))
        capsys.readouterr()
        before = records.load_job(ID)
        with (
            patch("boto3.client", side_effect=lambda name, **kwargs: ecs if name == "ecs" else sts),
            patch.object(SecurityHold, "status", check_state),
        ):
            main(arguments("inspect-runtime") + [
                "--incident-id", "INC-1", "--expected-revision", str(before.revision),
                "--expected-boundary", before.record["security_review_boundary"]["id"],
            ])
        report = json.loads(capsys.readouterr().out)
    assert observed_readonly == [True]
    assert report["runtime_inspection"]["registered_service_quiescent"] is True
    assert report["runtime_inspection"]["recovery_authorized"] is False
    assert report["runtime_inspection"]["execution_exclusion_verified"] is False
    assert report["observed_only"] is True and report["status"] == "held"
    assert records.load_job(ID) == before


def test_runtime_containment_cli_persists_intent_and_inspects_without_replay_or_state_write(
    configured_cli, store, database, monkeypatch, capsys
):
    from application.incident_runtime_containment import FIELD
    from tests.unit.test_incident_runtime_containment import native

    monkeypatch.setenv("SKY_STATE_WORKSPACE", store.workspace)
    records = PostgresDeploymentRecordStore(database, workspace=store.workspace)
    job = Records().job
    _, result, _, _, ecs, scaling = native()
    from unittest.mock import Mock

    sts = Mock(get_caller_identity=Mock(return_value={"Account": "111111111111"}))
    sts.meta.region_name = "ap-northeast-2"
    job["result"] = result
    records.save_job(ID, job, expected_revision=None)
    mutation = scaling.register_scalable_target.side_effect
    admitted = []

    def suspend(**kwargs):
        saved = records.load_job(ID)
        assert saved.record[FIELD]["phase"] == "applying"
        assert saved.record["promotion_automation_consent"] is None
        admitted.append(saved.revision)
        return mutation(**kwargs)

    scaling.register_scalable_target.side_effect = suspend
    clients = {"ecs": ecs, "sts": sts, "application-autoscaling": scaling}
    with (
        patch("interfaces.security_hold.RotatingDatabaseConnection", return_value=database),
        patch("boto3.client", side_effect=lambda name, **kwargs: clients[name]),
    ):
        main(arguments("place"))
        capsys.readouterr()
        before = records.load_job(ID)
        options = ["--incident-id", "INC-1", "--expected-boundary", before.record["security_review_boundary"]["id"]]
        request = arguments("contain-runtime") + options + ["--expected-revision", str(before.revision), "--confirm-runtime-containment"]
        main(request)
        response = json.loads(capsys.readouterr().out)
        assert response["runtime_containment"]["phase"] == "scale_down_requested"
        assert response["observed_only"] is False
        saved = records.load_job(ID)
        assert admitted == [before.revision + 1]
        main(request)
        assert json.loads(capsys.readouterr().out)["runtime_containment"] == response["runtime_containment"]
        assert records.load_job(ID) == saved
        assert scaling.register_scalable_target.call_count == ecs.update_service.call_count == 1
        original = SecurityHold.status
        readonly = []

        def status(service, *args):
            with service.writer.records.connection_factory() as db:
                readonly.append(db.execute("SHOW transaction_read_only").fetchone()[0])
            return original(service, *args)

        with patch.object(SecurityHold, "status", status):
            main(arguments("inspect-runtime-containment") + options + [
                "--expected-revision", str(saved.revision), "--expected-operation-id", saved.record[FIELD]["operation_id"],
            ])
        observed = json.loads(capsys.readouterr().out)
    assert observed["observed_only"] is True and readonly == ["on"]
    assert observed["runtime_containment"]["scale_down_configuration_observed"] is True
    assert observed["runtime_containment"]["recovery_authorized"] is False
    assert observed["runtime_containment"]["persisted_phase"] == "scale_down_requested"
    assert observed["promotion_blocked"] is True
    assert records.load_job(ID) == saved
    assert saved.record["security_hold"] == before.record["security_hold"]
    assert scaling.register_scalable_target.call_count == ecs.update_service.call_count == 1


def test_secret_access_cli_records_intent_and_inspects_without_releasing_or_replaying(
    configured_cli, store, database, monkeypatch, capsys, operating_review_setup, tmp_path
):
    from application.incident_secret_access import FIELD
    from tests.unit.test_incident_secret_access import configuration, fixture

    f = fixture(operating_review_setup)
    monkeypatch.setenv("SKY_STATE_WORKSPACE", store.workspace)
    records = PostgresDeploymentRecordStore(database, workspace=store.workspace)
    records.save_job(ID, f.records.job, expected_revision=None)
    path = configuration(tmp_path / "secret-registration.json", f.registration)
    original_policy = f.clients["secretsmanager"].put_resource_policy.side_effect
    admitted = []

    def policy(**kwargs):
        saved = records.load_job(ID)
        assert saved.record[FIELD]["phase"] == "applying"
        assert saved.record["promotion_automation_consent"] is None
        admitted.append(saved.revision)
        return original_policy(**kwargs)

    f.clients["secretsmanager"].put_resource_policy.side_effect = policy
    before = records.load_job(ID)
    options = ["--incident-secret-config", str(path), "--incident-id", "INC-1",
               "--expected-boundary", before.record["security_review_boundary"]["id"]]
    request = arguments("fence-secret-access") + options + ["--expected-revision", str(before.revision), "--confirm-secret-access-fence"]
    with (
        patch("interfaces.security_hold.RotatingDatabaseConnection", return_value=database),
        patch("adapters.aws.incident_secret_access.AwsIncidentSecretAccess", return_value=f.adapter),
    ):
        main(request)
        first = json.loads(capsys.readouterr().out)
        assert first["secret_access_fence"]["phase"] == "policy_recorded"
        saved = records.load_job(ID)
        assert admitted == [before.revision + 1]
        main(request)
        assert json.loads(capsys.readouterr().out)["secret_access_fence"] == first["secret_access_fence"]
        assert records.load_job(ID) == saved
        original = SecurityHold.status
        observed_readonly = []

        def status(service, *args):
            with service.writer.records.connection_factory() as db:
                observed_readonly.append(db.execute("SHOW transaction_read_only").fetchone()[0])
            return original(service, *args)

        with patch.object(SecurityHold, "status", status):
            main(arguments("inspect-secret-access") + options + [
                "--expected-revision", str(saved.revision), "--expected-operation-id", saved.record[FIELD]["operation_id"],
            ])
        inspected = json.loads(capsys.readouterr().out)
        assert inspected["secret_access_fence"]["policy_state"] == "runtime_roles_denied"
        assert inspected["secret_access_fence"]["iam_propagation_verified"] is False
        assert inspected["observed_only"] is True and observed_readonly == ["on"]
        main(arguments("status") + ["--incident-secret-config", str(path)])
        current = json.loads(capsys.readouterr().out)
        assert current["secret_access_fence"]["operation_id"] == saved.record[FIELD]["operation_id"]
        assert current["secret_access_fence"]["record_valid"] is True
        main(arguments("status"))
        assert json.loads(capsys.readouterr().out)["secret_access_fence"] == {"phase": "registration_required"}
    assert records.load_job(ID) == saved
    assert saved.record["security_hold"] == before.record["security_hold"]
    assert f.clients["secretsmanager"].put_resource_policy.call_count == 1


def test_credential_executor_cli_observes_original_task_without_metadata_write(
    configured_cli, store, database, monkeypatch, capsys, operating_review_setup
):
    from datetime import UTC, datetime, timedelta

    from tests.unit.test_credential_executor import app

    memory, _, inspection, _, clients = app(operating_review_setup)
    now = datetime.now(UTC)
    inspection.observer.clock = lambda: datetime.now(UTC)
    clients['ecs'].describe_tasks.return_value['tasks'][0]['stoppedAt'] = now - timedelta(seconds=1)
    monkeypatch.setenv('SKY_STATE_WORKSPACE', store.workspace)
    records = PostgresDeploymentRecordStore(database, workspace=store.workspace)
    records.save_job(ID, memory.job, expected_revision=None)
    before = records.load_job(ID)
    original = SecurityHold.status
    read_only = []

    def status(service, *args):
        with service.writer.records.connection_factory() as db:
            read_only.append(db.execute('SHOW transaction_read_only').fetchone()[0])
        return original(service, *args)

    with (
        patch('interfaces.security_hold.RotatingDatabaseConnection', return_value=database),
        patch('adapters.aws.credential_executor.AwsCredentialExecutorObserver', return_value=inspection.observer),
        patch.object(SecurityHold, 'status', status),
    ):
        main(arguments('inspect-credential-executor') + [
            '--incident-id', 'INC-1', '--expected-revision', str(before.revision),
            '--expected-boundary', before.record['security_review_boundary']['id'],
            '--expected-operation-id', before.record['security_credential_preparation']['operation_id'],
        ])
    result = json.loads(capsys.readouterr().out)
    assert result['credential_executor']['executor_state'] == 'stopped'
    assert result['credential_executor']['provider_requests_settled'] is False
    assert result['credential_executor']['recovery_authorized'] is False
    assert result['observed_only'] is True and read_only == ['on']
    assert records.load_job(ID) == before


def test_recovery_image_cli_reads_pinned_artifact_without_writes_or_access_release(
    configured_cli, store, database, monkeypatch, capsys, operating_review_setup, tmp_path
):
    from dataclasses import asdict
    from datetime import UTC, datetime

    from tests.unit.test_recovery_image_inspection import app, native

    memory, _, inspection, _, _ = app(operating_review_setup)
    adapter, _, _ = native(inspection.registration)
    adapter.clock = lambda: datetime.now(UTC)
    path = tmp_path / "recovery.json"
    path.write_text(json.dumps({"version": 1, **asdict(inspection.registration)}))
    monkeypatch.setenv("SKY_STATE_WORKSPACE", store.workspace)
    records = PostgresDeploymentRecordStore(database, workspace=store.workspace)
    records.save_job(ID, memory.job, expected_revision=None)
    before = records.load_job(ID)
    original = SecurityHold.status
    readonly = []

    def status(service, *args):
        with service.writer.records.connection_factory() as db:
            readonly.append(db.execute("SHOW transaction_read_only").fetchone()[0])
        return original(service, *args)

    with (
        patch("interfaces.security_hold.RotatingDatabaseConnection", return_value=database),
        patch("adapters.aws.recovery_image.AwsRecoveryImageInspector", return_value=adapter),
        patch.object(SecurityHold, "status", status),
    ):
        main(arguments("inspect-recovery-image") + [
            "--incident-id", "INC-1", "--expected-revision", str(before.revision),
            "--expected-boundary", before.record["security_review_boundary"]["id"],
            "--recovery-image-config", str(path),
        ])
    result = json.loads(capsys.readouterr().out)
    assert result["recovery_image"]["manifest_bytes_verified"] is True
    assert result["recovery_image"]["source_provenance_verified"] is False
    assert result["recovery_image"]["recovery_authorized"] is False
    assert result["observed_only"] is True and readonly == ["on"]
    assert result["promotion_blocked"] is True
    assert records.load_job(ID) == before
