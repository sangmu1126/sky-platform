"""Actual PostgreSQL finalization; external inspection is a controlled adapter."""

from dataclasses import replace
from unittest.mock import patch

import pytest

from application.build_reconciliation import BuildDeploymentReconciliation
from domain.access import LoginSource, Principal, Role
from tests.contract.test_build_consumer import Deployer
from tests.contract.test_build_consumer import database as database  # noqa: PLC0414
from tests.contract.test_build_consumer import setup as setup  # noqa: PLC0414


@pytest.fixture
def reconciliation(setup):
    consumer, operation, _ = setup
    consumer.deployer = Deployer()
    consumer.deployer.failure = OSError("create acknowledgement lost")
    consumer.deployer.result.update(verification={"http": "verified", "image": "verified"})
    assert consumer.consume_once() == "needs_attention"
    actor = Principal("alice", "team", Role.ADMIN, LoginSource.CORPORATE_SSO)
    service = BuildDeploymentReconciliation(
        consumer.store,
        consumer.builder,
        consumer.verifier,
        consumer.deployer,
        consumer.settings,
        revalidate=lambda: actor,
    )
    return service, actor, consumer.store.get(operation.id), consumer


def test_read_only_external_observation_completes_without_second_create_or_build(reconciliation):
    service, actor, operation, consumer = reconciliation
    result = service.observe(
        actor, operation.id, expected_version=operation.row_version, executor_stopped=True
    )
    assert result["status"] == "succeeded" and result["resubmission"] is False
    saved = consumer.store.get(operation.id)
    job = consumer.store.records.load_job(operation.command["job_id"]).record
    assert saved.status == job["status"] == "succeeded"
    assert saved.result == job["result"] and not saved.external_pending
    assert len(consumer.builder.requests) == len(consumer.deployer.calls) == 1
    consumer.store.admit(operation.application_id, "deploy", "next-operation", {})


def test_uncertain_final_commit_is_atomic_and_can_be_observed_without_reexecution(reconciliation):
    service, actor, operation, consumer = reconciliation
    before = consumer.store.records.load_job(operation.command["job_id"])
    with patch.object(consumer.store, "_event", side_effect=OSError("commit failed")), pytest.raises(OSError):
        service.observe(actor, operation.id, expected_version=operation.row_version, executor_stopped=True)
    assert consumer.store.get(operation.id) == operation
    assert consumer.store.records.load_job(operation.command["job_id"]) == before
    assert (
        service.observe(actor, operation.id, expected_version=operation.row_version, executor_stopped=True)[
            "status"
        ]
        == "succeeded"
    )
    assert len(consumer.builder.requests) == len(consumer.deployer.calls) == 1


@pytest.mark.parametrize("change", ["viewer", "version", "executor", "workflow", "http"])
def test_reconciliation_requires_current_identity_and_actual_observation(reconciliation, change):
    service, actor, operation, consumer = reconciliation
    version, stopped = operation.row_version, True
    if change == "viewer":
        actor = replace(actor, role=Role.VIEWER)
    elif change == "version":
        version += 1
    elif change == "executor":
        stopped = False
    elif change == "workflow":
        consumer.builder.run = {"run_id": 999, "succeeded": True}
    else:
        consumer.deployer.result["verification"]["http"] = "failed"
    with pytest.raises((ValueError, PermissionError)):
        service.observe(actor, operation.id, expected_version=version, executor_stopped=stopped)
    assert consumer.store.get(operation.id) == operation
    assert len(consumer.builder.requests) == len(consumer.deployer.calls) == 1
