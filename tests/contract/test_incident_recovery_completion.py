"""Atomic recovery publication: metadata, old leases and app barrier commit together."""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from adapters.state.incident_execution import PostgresIncidentExecutionControl
from adapters.state.incident_recovery import PostgresIncidentRecoveryCompletion
from tests.contract.test_incident_execution_fence import incident as incident  # noqa: PLC0414
from tests.contract.test_operation_store import database as database  # noqa: PLC0414
from tests.contract.test_operation_store import store as store  # noqa: PLC0414
from tests.unit.test_deployment_writes import ID


def verified(store, incident, *, pending=False):
    actor, options = incident
    op = store.admit("game", "deploy", "old", {})
    lease = store.claim(op.id, op.attempt_id, "old-worker")
    if pending:
        assert store.begin_external(lease, {"native_request": "not-settled"})
    PostgresIncidentExecutionControl(store, revalidate=lambda: actor).fence(actor, ID, **options)
    snapshot = store.records.load_job(ID)
    image = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/test@sha256:" + "b" * 64
    result = {
        "target": "aws-ecs-standard",
        "image": image,
        "url": "http://192.0.2.1:8080",
        "verification": {"http": "verified", "database_authentication": "verified"},
    }
    recovery = {
        "id": "f" * 32,
        "phase": "verified",
        "external_pending": False,
        "incident_id": options["incident_id"],
        "boundary_id": options["expected_boundary"],
        "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        "plan": {"image": image},
        "result": result,
    }
    revision = store.records.save_job(
        ID, {**snapshot.record, "security_recovery": recovery}, expected_revision=snapshot.revision
    )
    options["expected_revision"] = revision
    service = PostgresIncidentRecoveryCompletion(store, revalidate=lambda: actor)
    return actor, options, op, lease, result, service


def test_completion_replaces_runtime_and_never_revives_old_lease(store, incident):
    actor, options, op, lease, result, service = verified(store, incident)
    report = service.complete_recovery(actor, ID, recovery_id="f" * 32, **options)
    assert report["phase"] == "recovered" and report["hold_released"] and not report["automation_reenabled"]
    job = store.records.load_job(ID).record
    assert job["result"] == result and job["security_hold"] is None and job["security_recovery"] is None
    assert job["promotion_automation_consent"] is None
    assert job["security_review_boundary"]["id"] != options["expected_boundary"]
    assert (
        job["security_incident_history"][-1]["controls"]["security_hold"]["incident_id"]
        == options["incident_id"]
    )
    assert not store.heartbeat(lease) and not store.begin_external(lease, {"late": "request"})
    assert store.get(op.id).status == "failed"
    new = store.admit("game", "deploy", "new", {})
    assert store.claim(new.id, new.attempt_id, "new-worker")


def test_event_failure_rolls_back_runtime_update_and_barrier_release(store, incident):
    actor, options, op, lease, _result, service = verified(store, incident)
    before = store.records.load_job(ID)
    with patch.object(store, "_event", side_effect=OSError("event write failed")), pytest.raises(OSError):
        service.complete_recovery(actor, ID, recovery_id="f" * 32, **options)
    assert store.records.load_job(ID) == before and store.get(op.id).status == "running"
    assert not store.heartbeat(lease)
    observed = PostgresIncidentExecutionControl(store, revalidate=lambda: actor).inspect(actor, ID, **options)
    assert observed["sky_operation_admission_fenced"]


def test_pending_external_request_is_never_cleared_by_recovery_completion(store, incident):
    actor, options, op, lease, _result, service = verified(store, incident, pending=True)
    before = store.records.load_job(ID)
    with pytest.raises(ValueError, match="still require reconciliation"):
        service.complete_recovery(actor, ID, recovery_id="f" * 32, **options)
    assert store.records.load_job(ID) == before and store.get(op.id).external_pending
    assert not store.heartbeat(lease)
