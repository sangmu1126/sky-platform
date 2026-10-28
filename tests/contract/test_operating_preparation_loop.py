"""Real state DB: automatic review -> one durable prepare/outbox admission."""

from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import pytest

from adapters.state.operating_review_lock import PostgresOperatingReviewLocks
from adapters.state.postgres import PostgresDeploymentRecordStore
from application.database_promotion_workflow import PromotionPreparationAdmission
from application.operating_review import OperatingReview
from interfaces.operating_review import OperatingReviewController
from tests.contract.test_operation_store import database as database  # noqa: PLC0414
from tests.contract.test_operation_store import store as store  # noqa: PLC0414
from tests.unit.test_deployment_writes import principal
from tests.unit.test_operating_review import ID, NOW
from tests.unit.test_promotion_policy import policy_with_criteria, samples

pytest_plugins = ["tests.unit.test_operating_review"]


@pytest.fixture
def loop(database, store, operating_review_setup):
    fixture, policy, _ = operating_review_setup
    policy = policy_with_criteria(policy)
    samples(fixture)
    records = PostgresDeploymentRecordStore(database, workspace=store.workspace)
    records.save_job(ID, fixture.job)
    records.save_health(ID, fixture.health)
    review = OperatingReview(records)
    review.grant_automation(
        principal(),
        ID,
        policy,
        max_incremental_monthly_cents=3000,
        expires_at="2026-10-12T00:00:00+00:00",
        now=NOW,
    )
    controller = OperatingReviewController(records, {ID: policy}, clock=lambda: NOW)
    admission = PromotionPreparationAdmission(records, store, {ID: policy}, clock=lambda: NOW, enabled=True)
    locks = PostgresOperatingReviewLocks(database, workspace=store.workspace)
    return records, review, controller, admission, locks


def test_competing_ticks_admit_one_prepare_and_one_outbox_delivery(loop, store, database):
    _, _, controller, admission, locks = loop

    def tick(_):
        return controller.review_automations_once(
            lambda *_: principal(), coordinate=locks.acquire, prepare=admission
        )

    with ThreadPoolExecutor(max_workers=3) as workers:
        list(workers.map(tick, range(3)))
    repeated = tick(None)[0]
    assert repeated["status"] == "preparation_queued" and repeated["deployment_completed"] is False
    with database() as db:
        assert db.execute(
            "SELECT count(*) FROM sky_state.operations WHERE workspace=%s", (store.workspace,)
        ).fetchone() == (1,)
        assert db.execute(
            "SELECT count(*) FROM sky_state.outbox_events WHERE workspace=%s", (store.workspace,)
        ).fetchone() == (1,)
    operation = store.get(repeated["operation_id"])
    assert operation.kind == "db_dedicated_prepare" and not operation.external_pending


def test_revoked_consent_after_collection_blocks_even_previously_approved_proposal(loop):
    _, review, controller, admission, _ = loop
    prepare = Mock(wraps=admission)
    report = controller.review_automations_once(
        lambda *_: principal(), collect=lambda *_: review.revoke_automation(principal(), ID), prepare=prepare
    )
    assert report == [{"job_id": ID, "status": "review_blocked"}]
    prepare.admit.assert_not_called()


def test_metadata_only_default_and_insufficient_budget_never_admit(loop):
    records, _, controller, admission, _ = loop
    assert controller.review_automations_once(lambda *_: principal())[0]["status"] == "approved"
    # Budget is part of user consent. Lower it in persisted state, not a caller claim.
    snapshot = records.load_job(ID)
    snapshot.record["promotion_automation_consent"]["max_incremental_monthly_cents"] = 0
    records.save_job(ID, snapshot.record, expected_revision=snapshot.revision)
    prepare = Mock(wraps=admission)
    assert (
        controller.review_automations_once(lambda *_: principal(), prepare=prepare)[0]["status"]
        == "review_blocked"
    )
    prepare.admit.assert_not_called()
