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
