"""New-source recovery commits only verified runtime results under the old barrier."""

from copy import deepcopy
from unittest.mock import Mock, patch

import pytest

from adapters.state.source_recovery import PostgresSourceRecovery
from application.incident_source_recovery import IncidentSourceRecovery
from ports.remote_builds import digest
from tests.contract.test_operation_store import database as database  # noqa: PLC0414
from tests.contract.test_operation_store import store as store  # noqa: PLC0414
from tests.contract.test_source_build_execution import execution as execution  # noqa: PLC0414
from tests.unit.test_deployment_writes import ID
from tests.unit.test_incident_source_review import review as review  # noqa: PLC0414


@pytest.fixture
def recovery(execution, store):
    c = execution
    c.service.execute(c.r.actor, ID, approval_id=c.approval_id, **c.r.options)
    request = c.executions.load(c.r.actor, c.approval_id).record["request"]
    result = {
        k: request[k]
        for k in [
            "build_id",
            "source_digest",
            "plan_digest",
            "repository",
            "workflow_sha",
            "platform_code_sha",
        ]
    }
    result.update(
        version=1,
        request_digest=digest(request),
        run_id=123,
        platform="linux/amd64",
        image="111111111111.dkr.ecr.ap-northeast-2.amazonaws.com/sky-managed@sha256:" + "f" * 64,
        image_digest="sha256:" + "f" * 64,
    )
    c.builder.observe.return_value = {"run_id": 123, "succeeded": True}
    c.objects.result.return_value = result
    c.verifier.verify.return_value = {"image": result["image"], "manifest_bytes_verified": True}
    c.service.observe(c.r.actor, ID, approval_id=c.approval_id, **c.r.options)
    runtime = Mock()
    runtime.preflight.return_value = {
        "version": 1,
        "image": result["image"],
        "public_access": True,
        "owned_service": "fixture",
    }
    runtime.execute.return_value = {
        "target": "aws-ecs-express",
        "image": result["image"],
        "url": "https://fixture.invalid",
        "verification": {"http": "verified", "image": "verified"},
    }
    ledger = PostgresSourceRecovery(c.executions, store)
    ledger.initialize()

    # Approval validity is enforced against the DB clock. A local VM and the
    # host need not have sub-millisecond clock agreement, even on one machine.
    def clock():
        with store.records._connection() as connection:
            return connection.execute("SELECT clock_timestamp()").fetchone()[0].isoformat()

    service = IncidentSourceRecovery(c.service, ledger, runtime, clock=clock)
    c.recovery, c.recovery_store, c.runtime = service, ledger, runtime
    c.recovery_id = "a" * 32
    return c


def approve(c):
    return c.recovery.approve(
        c.r.actor,
        ID,
        approval_id=c.approval_id,
        recovery_id=c.recovery_id,
        review_ref="RECOVER",
        seconds=900,
        public_access=True,
        **c.r.options,
    )


def execute(c):
    return c.recovery.execute(
        c.r.actor, ID, approval_id=c.approval_id, recovery_id=c.recovery_id, **c.r.options
    )


def test_new_source_runtime_and_old_incident_are_committed_together(recovery, store, database):
    c = recovery
    before = store.records.load_job(ID)
    approved = approve(c)
    assert approved["phase"] == "approved" and not approved["hold_released"]
    assert store.records.load_job(ID) == before
    report = execute(c)
    assert report["phase"] == "recovered" and report["hold_released"] and not report["automation_reenabled"]
    job = store.records.load_job(ID)
    assert job.record["source_digest"] == c.r.artifact.source_digest
    assert job.record["source_ref"]["kind"] == "prepared"
    assert job.record["security_hold"] is None and job.record["security_recovery_source_review"] is None
    assert (
        job.record["security_incident_history"][-1]["prior_source_digest"] == before.record["source_digest"]
    )
    with database() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM sky_state.incident_execution_fences WHERE workspace=%s",
                (store.workspace,),
            ).fetchone()[0]
            == 0
        )
    with pytest.raises(ValueError):
        execute(c)
    c.runtime.execute.assert_called_once()


@pytest.mark.parametrize("change", ["image", "http", "missing-image-proof"])
def test_bad_runtime_result_never_releases_hold(recovery, store, change):
    c = recovery
    approve(c)
    if change == "image":
        c.runtime.execute.return_value["image"] = "wrong"
    elif change == "http":
        c.runtime.execute.return_value["verification"]["http"] = "failed"
    else:
        del c.runtime.execute.return_value["verification"]["image"]
    before = store.records.load_job(ID)
    with pytest.raises(OSError):
        execute(c)
    assert store.records.load_job(ID) == before
    assert c.recovery_store.load(c.r.actor, c.approval_id).record["phase"] == "needs_attention"
    c.runtime.restrict.assert_called_once()


def test_lost_final_commit_is_inspected_without_restricting_committed_service(recovery, store):
    c = recovery
    approve(c)
    original = c.recovery_store.complete

    def lost(*args):
        original(*args)
        raise OSError("Acknowledgement lost")

    with patch.object(c.recovery_store, "complete", side_effect=lost), pytest.raises(OSError):
        execute(c)
    c.runtime.restrict.assert_not_called()
    read = c.recovery.inspect(
        c.r.actor, ID, approval_id=c.approval_id, recovery_id=c.recovery_id, **c.r.options
    )
    assert read["phase"] == "recovered" and read["hold_released"]


def test_recovery_cannot_skip_fence_or_pending_effects(recovery, store, database):
    c = recovery
    with database() as db:
        db.execute("DELETE FROM sky_state.incident_execution_fences WHERE workspace=%s", (store.workspace,))
    with pytest.raises(ValueError):
        approve(c)
    c.runtime.execute.assert_not_called()


def test_new_image_recovery_does_not_discard_existing_database_binding(recovery, store):
    c = recovery
    snapshot = store.records.load_job(ID)
    c.r.options["expected_revision"] = store.records.save_job(
        ID,
        {**snapshot.record, "workload_database_binding": {"database": "exists"}},
        expected_revision=snapshot.revision,
    )
    with pytest.raises(ValueError):
        approve(c)
    c.runtime.execute.assert_not_called()


def test_final_event_failure_keeps_old_hold_and_fence(recovery, store, database):
    c = recovery
    approve(c)
    before = store.records.load_job(ID)
    with (
        patch.object(store, "_event", side_effect=OSError("event persistence failed")),
        pytest.raises(OSError),
    ):
        execute(c)
    assert store.records.load_job(ID) == before
    assert c.recovery_store.load(c.r.actor, c.approval_id).record["phase"] == "verified"
    c.runtime.restrict.assert_not_called()
    with database() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM sky_state.incident_execution_fences WHERE workspace=%s",
                (store.workspace,),
            ).fetchone()[0]
            == 1
        )


def test_verified_publication_can_resume_without_repeating_runtime_execution(recovery, store):
    c = recovery
    approve(c)
    with patch.object(store, "_event", side_effect=OSError("Commit rollback")), pytest.raises(OSError):
        execute(c)
    c.runtime.observe_verified.return_value = deepcopy(c.runtime.execute.return_value)
    result = c.recovery.finalize(
        c.r.actor, ID, approval_id=c.approval_id, recovery_id=c.recovery_id, **c.r.options
    )
    assert result["phase"] == "recovered"
    c.runtime.execute.assert_called_once()
    c.runtime.observe_verified.assert_called_once()
