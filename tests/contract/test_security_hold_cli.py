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
