"""Persisted boundary prevents pre-incident approval reuse; no production release."""

import pytest

from adapters.state.postgres import PostgresDeploymentRecordStore
from application.database_promotion_workflow import approved_snapshot
from application.operating_review import OperatingReview, deployment_observation_binding
from application.security_hold import SecurityHold
from domain.access import Role
from tests.contract.test_operation_store import database as database  # noqa: PLC0414
from tests.contract.test_operation_store import store as store  # noqa: PLC0414
from tests.unit.test_deployment_writes import principal
from tests.unit.test_operating_review import ID, NOW

pytest_plugins = ["tests.unit.test_operating_review"]


def test_persisted_incident_requires_new_observation_and_approval(database, store, operating_review_setup):
    memory, policy, _ = operating_review_setup
    records = PostgresDeploymentRecordStore(database, workspace=store.workspace)
    records.save_job(ID, memory.job, expected_revision=None)
    records.save_health(ID, memory.health, expected_revision=None)
    review = OperatingReview(records)
    previous = review.review(principal(), ID, policy, now=NOW)
    review.approve(principal(), ID, previous["proposal_id"], policy, now=NOW)
    hold = SecurityHold(records)
    hold.place(principal(role=Role.ADMIN), ID, incident_id="INC-1", reason="untrusted_artifact", now=NOW)
    held = records.load_job(ID)
    boundary = held.record["security_review_boundary"]
    hold.place(principal(role=Role.ADMIN), ID, incident_id="INC-1", reason="untrusted_artifact", now=NOW)
    assert records.load_job(ID).revision == held.revision
    assert held.record["promotion_automation_consent"] is None
    # Test-only direct metadata change models a future trusted release authority.
    records.save_job(ID, {**held.record, "security_hold": None}, expected_revision=held.revision)
    with pytest.raises(ValueError, match="not bound"):
        approved_snapshot(records, principal(), ID, previous["proposal_id"], policy, NOW)
    health = records.load_health_record(ID)
    observation = health.record[-1]
    observation["deployment_binding"] = deployment_observation_binding(records.load_job(ID).record)
    assert observation["deployment_binding"]["security_review_boundary"] == boundary
    records.save_health(ID, [observation], expected_revision=health.revision)
    current = review.review(principal(), ID, policy, now=NOW)
    assert current["status"] == "pending_approval" and current["proposal_id"] != previous["proposal_id"]
    with pytest.raises(ValueError):
        approved_snapshot(records, principal(), ID, current["proposal_id"], policy, NOW)
    review.approve(principal(), ID, current["proposal_id"], policy, now=NOW)
    assert (
        approved_snapshot(records, principal(), ID, current["proposal_id"], policy, NOW)[1]["status"]
        == "approved"
    )
