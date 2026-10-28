"""Real PostgreSQL lifecycle reads: no cross-release/tenant leaks or recovery."""

from dataclasses import replace
from uuid import uuid4

import pytest

from adapters.state.deployment_reads import PostgresDeploymentReads
from adapters.state.operations import PostgresOperationStore
from application.operating_lifecycle import OperatingLifecycle
from domain.access import Role
from tests.contract.test_deployment_reads import principal
from tests.contract.test_deployment_reads import setup as setup  # noqa: PLC0414

ID = "a" * 16


def test_owned_release_operations_are_bounded_and_never_publish_commands(setup):
    records, connect, _ = setup
    operations = PostgresOperationStore(connect, workspace=records.workspace)
    operations.initialize()
    job = {
        "id": ID,
        "application_id": "app",
        "organization_id": "org1",
        "created_by": "author",
        "status": "succeeded",
    }
    records.save_job(ID, job)
    command = {"job_id": ID, "requested_by": {"organization_id": "org1"}, "secret": "must-not-appear"}
    operation = operations.admit("app", "db_dedicated_prepare", uuid4().hex, command)
    lease = operations.claim(operation.id, operation.attempt_id, "original")
    operations.begin_external(lease, {"secret": "never-leak"})
    operations.require_attention(lease, {"stage": "untrusted-diagnostic", "secret": "never-leak"})
    service = OperatingLifecycle(PostgresDeploymentReads(connect, workspace=records.workspace))
    result = service.detail(principal(), ID)
    assert result["phase"] == "needs_attention"
    item = result["operations"][0]
    assert item["id"] == operation.id and item["stage"] is None
    assert not item["blind_retry_allowed"] and not item["recovery_enabled"]
    assert "attempt_id" not in item and "secret" not in str(result) and "never-leak" not in str(result)
    admin = service.detail(replace(principal(), role=Role.ADMIN), ID)["operations"][0]
    assert admin["attempt_id"] == operation.attempt_id and admin["row_version"] > 1
    other = "b" * 16
    records.save_job(other, {**job, "id": other})
    assert service.detail(principal(), other)["operations"] == []
    with pytest.raises(FileNotFoundError):
        service.detail(principal("org2"), ID)
    # GET cannot turn needs_attention into a new attempt or release reservation.
    assert operations.get(operation.id).status == "needs_attention"


def test_active_operation_cannot_disappear_behind_fifty_completed_records(setup):
    records, connect, _ = setup
    operations = PostgresOperationStore(connect, workspace=records.workspace)
    operations.initialize()
    records.save_job(
        ID,
        {
            "id": ID,
            "application_id": "app",
            "organization_id": "org1",
            "created_by": "author",
            "status": "succeeded",
        },
    )
    command = {"job_id": ID, "requested_by": {"organization_id": "org1"}}
    for _ in range(51):
        item = operations.admit("app", "db_dedicated_prepare", uuid4().hex, command)
        lease = operations.claim(item.id, item.attempt_id, "worker")
        assert operations.complete(lease, {"status": "prepared"})
    active = operations.admit("app", "db_dedicated_prepare", uuid4().hex, command)
    result = OperatingLifecycle(PostgresDeploymentReads(connect, workspace=records.workspace)).detail(
        principal(), ID
    )
    assert len(result["operations"]) == 50 and result["has_more_operations"]
    assert result["operations"][0]["id"] == active.id and result["phase"] == "executing"
