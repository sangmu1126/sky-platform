"""Real SQL reconciliation with synthetic trusted fencing, identity and observer."""

from contextlib import contextmanager
from dataclasses import replace
from unittest.mock import Mock, patch

import pytest

from application.available_target_preparation_recovery import AvailableTargetPreparationRecoveryAuthority
from application.database_preparation_recovery import PromotionPreparationRecovery
from application.database_promotion_workflow import KIND
from application.outbox import OutboxPublisher
from application.shared_database_consumer import AllocationQueueRouter, SharedDatabaseConsumer
from domain.access import Role
from ports.operations import ApplicationBusy
from ports.preparation_executor import CreateOnlyPreparationProfile, EcsPreparationExecutor
from ports.preparation_recovery import PreparationRecoveryFence
from ports.queue import ReceivedOperation
from ports.state import RecordConflict
from tests.contract.test_operation_store import count
from tests.contract.test_operation_store import database as database  # noqa: PLC0414
from tests.contract.test_operation_store import store as store  # noqa: PLC0414
from tests.contract.test_preparation_revalidation import persisted as persisted  # noqa: PLC0414
from tests.contract.test_preparation_revalidation import preparation as preparation  # noqa: PLC0414
from tests.contract.test_preparation_revalidation import revoke
from tests.unit.test_deployment_writes import principal
from tests.unit.test_operating_review import NOW

pytest_plugins = ["tests.unit.test_dedicated_database_admission"]


@pytest.fixture
def recovery(preparation, store, request):
    records, operation, worker, preparer, _, consumer = preparation
    worker.executor = getattr(request, "param", None)
    preparer.prepare.side_effect = OSError("Unknown provider outcome")
    assert consumer.consume_once() == "needs_attention"
    blocked = store.get(operation.id)
    admin = principal(role=Role.ADMIN)
    resolver = Mock(return_value=admin)
    fence = PreparationRecoveryFence(
        store.workspace,
        blocked.id,
        blocked.attempt_id,
        blocked.row_version,
        "evidence:fixture/executor-stopped",
        Mock(),
    )

    @contextmanager
    def hold(snapshot):
        assert snapshot == blocked
        yield fence

    authority = Mock(hold=hold)
    observer = Mock()
    observer.observe.return_value = {
        "operation_id": operation.id,
        "plan_id": blocked.command["proposal"]["plan"]["plan_id"],
        "binding": blocked.command["proposal"]["plan"]["target"],
        "status": "available",
        "verified_scope": "rds_ownership_network_tls",
        "encrypted": True,
        "publicly_accessible": False,
        "resource_id": "db-" + "A" * 26,
        "password": "never-persist-this",
    }
    service = PromotionPreparationRecovery(
        records, store, worker.policies, observer, resolver, authority, clock=lambda: NOW
    )
    return service, admin, blocked, fence, observer, worker, preparer


def resume(recovery):
    service, admin, blocked, *_ = recovery
    return service.resume(admin, blocked.id, blocked.attempt_id, blocked.row_version)


@pytest.mark.parametrize(
    "recovery",
    [None, EcsPreparationExecutor("arn:aws:ecs:ap-northeast-2:111111111111:task/sky-worker/" + "a" * 32)],
    indirect=True,
)
def test_trusted_observation_requeues_same_operation_and_worker_completes_without_creation(
    recovery, store, database
):
    _service, _, blocked, fence, observer, worker, preparer = recovery
    with patch("boto3.client", side_effect=AssertionError("Cloud clients forbidden")):
        receipt = resume(recovery)
        queued = store.get(blocked.id)
        assert receipt["status"] == queued.status == "queued"
        assert receipt["data_routing_changed"] is False
        assert queued.attempt_id != blocked.attempt_id
        assert queued.external_receipt["observation"]["executor_exclusion_evidence_ref"] == fence.evidence_ref
        assert queued.external_receipt["resolution"]["outcome"] == "resume"
        assert queued.external_receipt["observation"]["recovery_operator"] == {
            "organization_id": "org1",
            "user_id": "user1",
        }
        assert "never-persist-this" not in str(queued)
        assert count(store, database, "mutation_scopes") == 1
        assert count(store, database, "operations") == 1
        assert count(store, database, "outbox_events") == 2
        with pytest.raises(ApplicationBusy):
            store.admit(blocked.application_id, "deploy", "must-still-wait", {})
        with pytest.raises(RecordConflict):
            resume(recovery)
        observer.observe.assert_called_once()
        sent = []
        publisher = OutboxPublisher(
            store,
            AllocationQueueRouter(store, None, None, promotion_queue=Mock(publish=sent.append)),
            "recovered-preparation-publisher",
        )
        assert publisher.dispatch_once().confirmed == 1
        queue = Mock(receive=Mock(return_value=ReceivedOperation("new-receipt", sent[0].message())))
        worker.executor = EcsPreparationExecutor(
            "arn:aws:ecs:ap-northeast-2:111111111111:task/replacement/" + "b" * 32
        )
        consumer = SharedDatabaseConsumer(store, queue, worker, kind=KIND)
        assert consumer.consume_once() == "succeeded"
        assert consumer.consume_once() == "duplicate"
    final = store.get(blocked.id)
    assert final.external_intent == blocked.external_intent
    assert final.result["promotion_status"] == "not_started" and not final.result["ready_to_cutover"]
    assert count(store, database, "mutation_scopes") == 0
    preparer.prepare.assert_called_once()  # Original uncertain request only.


@pytest.mark.parametrize(
    "change",
    ["missing_authority", "fence", "foreign_fence", "operator", "approval", "cost", "receipt", "absent"],
)
def test_unverified_recovery_retains_original_evidence_and_reservation(recovery, store, database, change):
    service, _, blocked, fence, observer, _, _ = recovery
    if change == "missing_authority":
        service.authority = None
    elif change == "fence":
        fence.check.side_effect = OSError("Exclusion no longer held")
    elif change == "foreign_fence":

        @contextmanager
        def wrong(_operation):
            yield replace(fence, workspace="other")

        service.authority = Mock(hold=wrong)
    elif change == "operator":
        service.resolve_principal.return_value = principal(role=Role.DEPLOYER)
    elif change in {"approval", "cost"}:
        revoke(change, service.validator.records, service.validator)
    elif change == "receipt":
        observer.observe.return_value["operation_id"] = "other"
    else:
        observer.observe.side_effect = ValueError("Dedicated target outcome remains unverified")
    with (
        patch("boto3.client", side_effect=AssertionError("Cloud clients forbidden")),
        pytest.raises((ValueError, PermissionError, OSError)),
    ):
        resume(recovery)
    assert store.get(blocked.id) == blocked
    assert count(store, database, "mutation_scopes") == 1
    assert count(store, database, "outbox_events") == 1
    with pytest.raises(ApplicationBusy):
        store.admit(blocked.application_id, "deploy", "unsafe-replacement", {})


@pytest.mark.parametrize("change", ["approval", "operator", "fence"])
def test_authority_change_during_observation_is_checked_before_resolution(recovery, store, change):
    service, _, blocked, fence, observer, _, _ = recovery
    receipt = observer.observe.return_value

    def observe(_plan, *, operation_id, guard):
        guard()
        if change == "approval":
            revoke("approval", service.validator.records, service.validator)
        elif change == "operator":
            service.resolve_principal.return_value = principal(role=Role.VIEWER)
        else:
            fence.check.side_effect = OSError("Exclusion lost")
        return receipt

    observer.observe.side_effect = observe
    with pytest.raises((ValueError, PermissionError, OSError)):
        resume(recovery)
    assert store.get(blocked.id) == blocked


def test_resolution_commit_response_loss_does_not_repeat_observation_or_enqueue(recovery, store, database):
    _service, _, blocked, _, observer, _, _ = recovery
    resolve = store.resolve_attention

    def lost_response(*args, **kwargs):
        assert resolve(*args, **kwargs)
        raise OSError("Resolution committed; response lost")

    with patch.object(store, "resolve_attention", side_effect=lost_response) as called:
        with pytest.raises(OSError, match="response lost"):
            resume(recovery)
        with pytest.raises(RecordConflict):
            resume(recovery)
        called.assert_called_once()
    assert store.get(blocked.id).status == "queued"
    assert count(store, database, "operations") == 1
    assert count(store, database, "outbox_events") == 2
    assert count(store, database, "mutation_scopes") == 1
    observer.observe.assert_called_once()


ECS_EXECUTOR = EcsPreparationExecutor("arn:aws:ecs:ap-northeast-2:111111111111:task/sky-worker/" + "a" * 32)


def available_authority(recovery, store):
    service, _, blocked, _, observer, _, _ = recovery
    profile = CreateOnlyPreparationProfile(
        "arn:aws:ecs:ap-northeast-2:111111111111:task-definition/sky-worker:7",
        (("worker", "sha256:" + "c" * 64),),
    )
    stopped = Mock(workspace=store.workspace, profile=profile)
    stopped.observe.return_value = {
        "workspace": store.workspace,
        "operation_id": blocked.id,
        "attempt_id": blocked.attempt_id,
        "operation_version": blocked.row_version,
        "executor": blocked.external_intent["executor"],
        "execution_profile": profile.record(),
        "scope": "ecs_executor_stopped_only",
        "evidence_ref": "evidence:ecs-stopped/" + "d" * 64,
        "stopped_at": "2026-10-10T23:59:00+00:00",
    }
    clock = [0]
    authority = AvailableTargetPreparationRecoveryAuthority(
        store, stopped, observer, monotonic=lambda: clock[0]
    )
    service.authority = authority
    return authority, stopped, observer, clock


@pytest.mark.parametrize("recovery", [ECS_EXECUTOR], indirect=True)
def test_available_target_authority_requeues_with_auditable_evidence_and_no_creation(
    recovery, store, database
):
    _, _, blocked, _, _, worker, preparer = recovery
    _, stopped, target, _ = available_authority(recovery, store)
    with patch("boto3.client", side_effect=AssertionError("Cloud clients forbidden")):
        assert resume(recovery)["status"] == "queued"
        queued = store.get(blocked.id)
        proof = queued.external_receipt["observation"]["executor_exclusion_evidence"]
        assert proof["policy_id"] == "stopped-create-only-existing-protected-target-v1"
        assert proof["execution_profile"] == stopped.profile.record()
        assert proof["requests_cancelled"] is False
        assert proof["target_resource_id"] == target.observe.return_value["resource_id"]
        assert count(store, database, "mutation_scopes") == 1
        assert count(store, database, "outbox_events") == 2
        assert worker.execute(queued.id, queued.attempt_id)["status"] == "succeeded"
    preparer.prepare.assert_called_once()  # Original failed preparation only.
    assert count(store, database, "mutation_scopes") == 0
    assert store.get(blocked.id).external_intent == blocked.external_intent


@pytest.mark.parametrize("recovery", [ECS_EXECUTOR], indirect=True)
@pytest.mark.parametrize(
    "change",
    [
        "absent",
        "replaced",
        "expired",
        "task_scope",
        "profile",
        "approval",
        "profile_revoked",
        "observation_mismatch",
    ],
)
def test_available_target_recovery_requires_stable_target_and_current_approval(
    recovery, store, database, change
):
    service, _, blocked, _, _, _, _ = recovery
    _, stopped, target, clock = available_authority(recovery, store)
    original = dict(target.observe.return_value)
    if change == "absent":
        target.observe.side_effect = ValueError("Target not available")
    elif change == "replaced":
        target.observe.side_effect = [original, {**original, "resource_id": "db-" + "B" * 26}]
    elif change == "task_scope":
        stopped.observe.return_value["workspace"] = "other"
    elif change == "profile":
        stopped.observe.return_value["execution_profile"] = {"untrusted": True}
    elif change == "observation_mismatch":
        service.observer = Mock(observe=Mock(return_value={**original, "resource_id": "db-" + "B" * 26}))
    else:
        calls = []

        def observe(_plan, *, operation_id, guard):
            guard()
            calls.append(True)
            if len(calls) == 1:
                if change == "expired":
                    clock[0] = 120
                elif change == "profile_revoked":
                    stopped.profile = CreateOnlyPreparationProfile(
                        stopped.profile.task_definition_arn[:-1] + "8", stopped.profile.images
                    )
                else:
                    revoke("approval", service.validator.records, service.validator)
            return original

        target.observe.side_effect = observe
    with pytest.raises((ValueError, OSError)):
        resume(recovery)
    assert store.get(blocked.id) == blocked
    assert count(store, database, "mutation_scopes") == 1
    assert count(store, database, "outbox_events") == 1


@pytest.mark.parametrize("recovery", [ECS_EXECUTOR], indirect=True)
def test_available_target_fence_cannot_be_reused_after_context_exit(recovery, store):
    _, _, blocked, *_ = recovery
    authority, _, _, _ = available_authority(recovery, store)
    with authority.hold(blocked) as fence:
        fence.check()
    with pytest.raises(OSError, match="expired"):
        fence.check()
    assert store.get(blocked.id) == blocked
