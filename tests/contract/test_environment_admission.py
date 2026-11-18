"""PostgreSQL review/gate consumption and operation admission are atomic."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest

from adapters.state.deployment_admission import PostgresDeploymentAdmission
from adapters.state.environment_admission import PostgresEnvironmentExecutionAdmission
from adapters.state.environment_gates import PostgresPreservationGates
from adapters.state.environment_reviews import PostgresEnvironmentReviews
from adapters.state.operations import PostgresOperationStore
from application.environment_admission import RegisteredEnvironmentExecution
from application.environment_execution_worker import RegisteredEnvironmentExecutionWorker
from application.environment_jobs import RegisteredEnvironmentJob
from domain.access import LoginSource, Principal, ResourceOwner, Role
from domain.environment_transition import BASELINE_CAPABILITIES
from engine.environment_transition import assess_environment_transition
from ports.operations import IdempotencyConflict
from tests.contract.test_database_migration_reviews import database as database  # noqa: PLC0414
from tests.unit.test_database_transfer import transfer
from tests.unit.test_environment_gate_review import case, observations

ACTOR = Principal("alice", "org", Role.DEPLOYER, LoginSource.CORPORATE_SSO)


@pytest.fixture
def stores(database):
    admission = PostgresDeploymentAdmission(
        PostgresOperationStore(database, workspace=uuid4().hex),
        account_id="111111111111",
        region="ap-northeast-2",
    )
    execution = PostgresEnvironmentExecutionAdmission(admission, current_principal=lambda value: value)
    execution.initialize()
    with database() as db:
        db.execute(
            """INSERT INTO sky_state.application_owners
            (workspace,application_id,organization_id,created_by) VALUES(%s,'app','org','alice')""",
            (admission.operations.workspace,),
        )
    return (
        execution,
        PostgresEnvironmentReviews(admission),
        PostgresPreservationGates(admission, current_principal=lambda value: value),
    )


def prepared(stores, database):
    _execution_store, reviews, gates = stores
    policy, _ = case()
    with database() as db:
        now = db.execute("SELECT clock_timestamp()").fetchone()[0]
    requirements = tuple(value for value in policy.requirements if value.capability in BASELINE_CAPABILITIES)
    collected = tuple(
        value
        for value in observations(policy, now - timedelta(seconds=1), through="G8")
        if value.requirement in requirements
    )
    report = assess_environment_transition(
        policy.scope, requirements, collected, now=now, max_age_seconds=300
    )
    review = reviews.record(ACTOR, "registered-route", report)
    review = reviews.approve(
        ACTOR,
        review.id,
        registration_id=review.registration_id,
        report_id=review.report_id,
    )
    gate = None
    for index in range(8):
        name = "G" + str(index)
        gate = gates.record(
            ACTOR,
            "registered-route",
            policy,
            name,
            observations(policy, now - timedelta(seconds=1), through=name),
            request_key="collect-" + name,
        )
    job = RegisteredEnvironmentJob(
        "game",
        ResourceOwner("org", "alice"),
        transfer(),
        now + timedelta(minutes=5),
        "http://127.0.0.1:8780/",
        "b" * 64,
    )
    return RegisteredEnvironmentExecution(job, policy, "registered-route"), review, gate


def submit(store, registered, review, gate, request_key="one"):
    return store.submit(
        ACTOR,
        registered,
        review_id=review.id,
        report_id=review.report_id,
        gate_record_id=gate["record_id"],
        request_key=request_key,
        confirm_write_pause=True,
        confirm_websocket_reconnect=True,
    )


def counts(store, database):
    with database() as db:
        return tuple(
            db.execute(
                "SELECT count(*) FROM sky_state." + table + " WHERE workspace=%s",
                (store.operations.workspace,),
            ).fetchone()[0]
            for table in (
                "operations",
                "outbox_events",
                "mutation_scopes",
                "environment_execution_admissions",
            )
        )


def test_current_review_and_g7_are_consumed_with_one_operation(stores, database):
    store, *_ = stores
    registered, review, gate = prepared(stores, database)
    operation = submit(store, registered, review, gate)
    assert submit(store, registered, review, gate) == operation
    assert operation.kind == "environment_transfer" and operation.status == "queued"
    assert operation.command["registration_revision"] == registered.revision
    assert operation.command["review_id"] == review.id
    assert operation.command["gate_record_id"] == gate["record_id"]
    assert counts(store, database) == (1, 1, 1, 1)
    assert store.revalidate(ACTOR, registered, operation)
    store.check_ready()


def execution_worker(store, registered, *, effect):
    resources = Mock(
        verify=Mock(
            return_value={
                "execution_revision": registered.revision,
                "verified": True,
                "evidence_refs": ["WPI-" + "a" * 64, "WRI-" + "b" * 64],
            }
        )
    )
    worker = RegisteredEnvironmentExecutionWorker(
        store.operations,
        store,
        {registered.job.id: registered},
        lambda user_id, organization_id: (
            ACTOR if (user_id, organization_id) == (ACTOR.user_id, ACTOR.organization_id) else None
        ),
        resources,
        effect,
        owner="reviewed-worker",
        clock=lambda: registered.job.expires_at - timedelta(minutes=4),
    )
    return worker, resources


def test_registered_worker_revalidates_real_admission_and_finishes(stores, database):
    store, *_ = stores
    registered, review, gate = prepared(stores, database)
    operation = submit(store, registered, review, gate)
    effect = Mock(return_value={"result_ref": "registered-environment-result"})
    worker, resources = execution_worker(store, registered, effect=effect)

    assert worker.execute(operation.id, operation.attempt_id) == {"status": "succeeded"}
    saved = store.operations.get(operation.id)
    assert saved.status == "succeeded" and saved.external_pending is False
    assert saved.result == {"result_ref": "registered-environment-result"}
    resources.verify.assert_called_once()
    effect.assert_called_once()
    assert saved.checkpoint["cutover_steps"][0]["stage"] == "resource_ownership"


def test_registered_worker_parks_uncertain_effect_and_never_replays(stores, database):
    store, *_ = stores
    registered, review, gate = prepared(stores, database)
    operation = submit(store, registered, review, gate)
    effect = Mock(side_effect=OSError("provider response lost"))
    worker, _resources = execution_worker(store, registered, effect=effect)

    assert worker.execute(operation.id, operation.attempt_id) == {"status": "needs_attention"}
    saved = store.operations.get(operation.id)
    assert saved.status == "needs_attention" and saved.external_pending is True
    assert worker.execute(operation.id, operation.attempt_id) == {"status": "not_claimed"}
    effect.assert_called_once()


def test_gate_is_single_use_and_request_key_cannot_change_meaning(stores, database):
    store, *_ = stores
    registered, review, gate = prepared(stores, database)
    submit(store, registered, review, gate)
    with pytest.raises(IdempotencyConflict):
        submit(store, registered, review, gate, request_key="other")
    with pytest.raises(IdempotencyConflict):
        store.submit(
            ACTOR,
            registered,
            review_id=review.id,
            report_id="ENV-" + "f" * 64,
            gate_record_id=gate["record_id"],
            request_key="one",
            confirm_write_pause=True,
            confirm_websocket_reconnect=True,
        )
    assert counts(store, database) == (1, 1, 1, 1)


def test_concurrent_same_request_creates_one_operation_and_outbox(stores, database):
    store, *_ = stores
    registered, review, gate = prepared(stores, database)
    with ThreadPoolExecutor(max_workers=6) as workers:
        results = list(workers.map(lambda _: submit(store, registered, review, gate), range(12)))
    assert all(value == results[0] for value in results)
    assert counts(store, database) == (1, 1, 1, 1)


def test_revoked_review_cannot_create_any_durable_work(stores, database):
    store, reviews, _gates = stores
    registered, review, gate = prepared(stores, database)
    assert reviews.revoke(ACTOR, review.id)
    with pytest.raises(ValueError, match="not current and approved"):
        submit(store, registered, review, gate)
    assert counts(store, database) == (0, 0, 0, 0)


def test_failure_after_operation_insert_rolls_back_every_admission_row(stores, database):
    store, *_ = stores
    registered, review, gate = prepared(stores, database)
    admit = store.operations._admit_in_transaction

    def fail_after_insert(*args, **kwargs):
        admit(*args, **kwargs)
        raise OSError("ledger unavailable")

    with (
        patch.object(store.operations, "_admit_in_transaction", side_effect=fail_after_insert),
        pytest.raises(OSError, match="ledger unavailable"),
    ):
        submit(store, registered, review, gate)
    assert counts(store, database) == (0, 0, 0, 0)
