"""Inspect a real committed recovery after a simulated lost acknowledgement."""

import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from adapters.state.postgres import PostgresDeploymentRecordStore
from application.incident_recovery_inspection import IncidentRecoveryInspection
from interfaces.b_runtime import main
from tests.contract.test_incident_execution_fence import incident as incident  # noqa: PLC0414
from tests.contract.test_incident_recovery_completion import verified
from tests.contract.test_operation_store import database as database  # noqa: PLC0414
from tests.contract.test_operation_store import store as store  # noqa: PLC0414
from tests.unit.test_deployment_writes import ID
from tests.unit.test_security_hold_cli import configured_cli as configured_cli  # noqa: PLC0414


def prepare(store, incident):
    actor, options, op, lease, result, completion = verified(store, incident)
    snapshot = store.records.load_job(ID)
    record = snapshot.record["security_recovery"]
    record.update(version=1, approved_at=(datetime.now(UTC) - timedelta(seconds=2)).isoformat())
    options["expected_revision"] = store.records.save_job(
        ID, snapshot.record, expected_revision=snapshot.revision
    )
    return actor, options, op, lease, result, completion


def test_lost_final_ack_is_observable_without_replaying_or_reactivating(store, incident, database):
    actor, options, op, lease, _result, completion = prepare(store, incident)

    def lost_ack():
        completion.complete_recovery(actor, ID, recovery_id="f" * 32, **options)
        raise OSError("commit acknowledgement lost")

    with pytest.raises(OSError):
        lost_ack()
    committed = store.records.load_job(ID)
    old_operation = store.get(op.id)

    @contextmanager
    def readonly():
        with database() as db:
            db.execute("SET TRANSACTION READ ONLY")
            yield db

    inspector = IncidentRecoveryInspection(
        PostgresDeploymentRecordStore(readonly, workspace=store.workspace),
        clock=lambda: datetime.now(UTC).isoformat(),
        revalidate=lambda: actor,
    )
    options["expected_revision"] = committed.revision
    report = inspector.inspect(actor, ID, recovery_id="f" * 32, **options)
    assert (
        report["completion_recorded"]
        and report["current_result_matches_record"]
        and not report["live_runtime_verified"]
    )
    assert store.records.load_job(ID) == committed and store.get(op.id) == old_operation
    assert not store.heartbeat(lease)
    with readonly() as db:
        assert db.execute("SHOW transaction_read_only").fetchone() == ("on",)


def test_not_committed_final_transaction_remains_verified_and_fenced(store, incident):
    actor, options, op, lease, _result, completion = prepare(store, incident)
    before = store.records.load_job(ID)
    with patch.object(store, "_event", side_effect=OSError("rollback")), pytest.raises(OSError):
        completion.complete_recovery(actor, ID, recovery_id="f" * 32, **options)
    report = IncidentRecoveryInspection(
        store.records, clock=lambda: datetime.now(UTC).isoformat(), revalidate=lambda: actor
    ).inspect(actor, ID, recovery_id="f" * 32, **options)
    assert report["persisted_outcome"] == "completion_not_recorded" and report["active_hold_recorded"]
    assert not report["automatic_retry_allowed"] and store.records.load_job(ID) == before
    assert not store.heartbeat(lease) and store.get(op.id).status == "running"


def test_cli_uses_actual_sql_readonly_transactions_and_hides_unregistered_data(
    store, incident, database, configured_cli, monkeypatch, capsys
):
    import psycopg

    actor, options, _op, _lease, _result, completion = prepare(store, incident)
    completion.complete_recovery(actor, ID, recovery_id="f" * 32, **options)
    before = store.records.load_job(ID)
    options["expected_revision"] = before.revision
    monkeypatch.setenv("SKY_STATE_WORKSPACE", store.workspace)
    args = [
        "security-hold",
        "inspect-recovery",
        "--job-id",
        ID,
        "--user-id",
        actor.user_id,
        "--organization-id",
        actor.organization_id,
        "--incident-id",
        options["incident_id"],
        "--expected-boundary",
        options["expected_boundary"],
        "--expected-revision",
        str(before.revision),
        "--recovery-id",
        "f" * 32,
    ]
    native = IncidentRecoveryInspection.inspect

    def checked(self, *a, **kw):
        with self.writer.records._connection() as db:
            assert db.execute("SHOW transaction_read_only").fetchone() == ("on",)
            with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
                db.execute("UPDATE sky_state.metadata_records SET revision=revision WHERE false")
        return native(self, *a, **kw)

    with (
        patch("interfaces.incident_recovery_inspection.RotatingDatabaseConnection", return_value=database),
        patch.object(IncidentRecoveryInspection, "inspect", checked),
        patch("boto3.client", side_effect=AssertionError("AWS")),
    ):
        main(args)
    report = json.loads(capsys.readouterr().out)["incident_recovery_inspection"]
    assert report["completion_recorded"] and report["read_only"]
    assert "controls" not in report and "plan" not in report and "result" not in report
    assert store.records.load_job(ID) == before
