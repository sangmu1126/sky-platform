"""A timer must not access workload telemetry with stale automation consent."""

from dataclasses import replace
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import pytest

from domain.access import Role
from interfaces.b_runtime import main
from interfaces.operating_review import OperatingReviewController
from tests.unit.test_deployment_writes import principal
from tests.unit.test_operating_review import ID, NOW
from tests.unit.test_promotion_policy import policy_with_criteria

pytest_plugins = ["tests.unit.test_operating_automation_worker"]


def later(seconds):
    return (datetime.fromisoformat(NOW) + timedelta(seconds=seconds)).isoformat()


@pytest.fixture
def authorized(operating_review_setup):
    from tests.unit.test_promotion_policy import samples

    records, policy, service = operating_review_setup
    policy = policy_with_criteria(policy)
    policy = replace(policy, cost_quote=replace(policy.cost_quote, valid_until=later(30)))
    samples(records)
    service.grant_automation(
        principal(), ID, policy, max_incremental_monthly_cents=3000, expires_at=later(60), now=NOW
    )
    records.save_calls = 0
    clock = [NOW]
    controller = OperatingReviewController(records, {ID: policy}, clock=lambda: clock[0])
    return records, policy, service, clock, controller


@pytest.mark.parametrize("change", ["expired", "scope", "quote", "budget", "policy", "inactive"])
def test_invalid_automation_never_collects(authorized, change):
    records, policy, _, _, controller = authorized
    consent = records.job["promotion_automation_consent"]
    if change == "expired":
        consent["expires_at"] = NOW
    elif change == "scope":
        consent["source"]["instance_id"] = "other-pool"
    elif change == "quote":
        controller.policies[ID] = replace(policy, cost_quote=replace(policy.cost_quote, valid_until=NOW))
    elif change == "budget":
        consent["max_incremental_monthly_cents"] = 1
    elif change == "policy":
        controller.policies[ID] = replace(policy, isolation_required=True)
    else:
        records.job["deployment_state"] = "deleted"
    collect = Mock()
    report = controller.review_automations_once(Mock(return_value=principal()), collect=collect)
    assert report[0]["status"] == "review_blocked"
    collect.assert_not_called()
    assert records.save_calls == 0
    assert "operating_proposal" not in records.job


@pytest.mark.parametrize(
    "change", ["revoke", "expire", "replace_consent", "quote_expire", "member_revoked", "source"]
)
def test_changed_authorization_during_collection_never_writes_approval(authorized, change):
    records, policy, service, clock, controller = authorized

    def collect(*_):
        if change == "revoke":
            service.revoke_automation(principal(), ID)
        elif change == "expire":
            clock[0] = later(60)
        elif change == "replace_consent":
            service.grant_automation(
                principal(),
                ID,
                policy,
                max_incremental_monthly_cents=4000,
                expires_at=later(60),
                now=NOW,
            )
        elif change == "quote_expire":
            clock[0] = later(30)
        elif change == "source":
            records.job["source_digest"] = "c" * 64

    resolver = (
        Mock(side_effect=[principal(), principal(role=Role.VIEWER)])
        if change == "member_revoked"
        else Mock(return_value=principal())
    )
    collection = Mock(side_effect=collect)
    assert controller.review_automations_once(resolver, collect=collection)[0]["status"] == "review_blocked"
    collection.assert_called_once()
    assert "operating_proposal" not in records.job


def test_current_consent_collects_and_approves_metadata_only(authorized):
    records, _, _, _, controller = authorized
    collect = Mock()
    resolver = Mock(side_effect=[principal(), principal(role=Role.ADMIN)])
    report = controller.review_automations_once(resolver, collect=collect)
    assert report[0]["status"] == "approved"
    assert resolver.call_count == 2
    collect.assert_called_once()
    assert records.job["operating_proposal"]["execution_status"] == "unsupported_by_sky"


def test_no_consent_runtime_collection_mode_never_constructs_workload_client(
    registered, operating_review_setup, capsys
):
    records, _, _ = operating_review_setup
    with (
        patch("interfaces.operating_review_worker.load_hosted_identity", return_value=Mock()),
        patch("interfaces.operating_review_worker.RotatingDatabaseConnection", return_value=Mock()),
        patch("interfaces.operating_review_worker.check_database_ready"),
        patch("interfaces.operating_review_worker.PostgresDeploymentRecordStore", return_value=records),
        patch(
            "adapters.aws.shared_database.AwsSharedDatabaseAllocator",
            side_effect=AssertionError("Unneeded workload access"),
        ) as allocator,
    ):
        main(["worker", "--mode", "operating-review", "--once", "--collect-capacity-metrics"])
    allocator.assert_not_called()
    assert "no_automation_consent" in capsys.readouterr().out


def test_authorized_runtime_collection_audits_pool_lazily_once(registered, capsys):
    settings, _ = registered
    pool = settings.source.pool
    controller = Mock()
    controller.service.writer.snapshot.return_value.record = {
        "workload_database_binding": {
            "instance_id": pool.instance_id,
            "account_id": pool.account_id,
            "region": pool.region,
        }
    }
    policy = Mock(target=Mock(account_id=pool.account_id), capacity_criteria=Mock(collector_id="registered"))

    def review(_resolver, *, collect, coordinate):
        assert callable(coordinate)
        collect(principal(), ID, policy)
        collect(principal(), ID, policy)
        return []

    controller.review_automations_once.side_effect = review
    audit = Mock()
    audit._audit.return_value = ("db.internal", 5432, "registered-secret")
    audit._admin_credentials.return_value = ("user", "synthetic-secret")
    with (
        patch("interfaces.operating_review_worker.load_hosted_identity", return_value=Mock()),
        patch("interfaces.operating_review_worker.RotatingDatabaseConnection", return_value=Mock()),
        patch("interfaces.operating_review_worker.check_database_ready"),
        patch("interfaces.operating_review_worker.PostgresDeploymentRecordStore", return_value=Mock()),
        patch("interfaces.operating_review_worker.OperatingReviewController", return_value=controller),
        patch("adapters.aws.shared_database.AwsSharedDatabaseAllocator", return_value=audit) as allocator,
        patch("adapters.database.workload_metrics.PostgresWorkloadMetrics") as metrics,
        patch("application.capacity_observation.CapacityObservationRecorder") as recorder,
    ):
        main(["worker", "--mode", "operating-review", "--once", "--collect-capacity-metrics"])
    allocator.assert_called_once()
    audit._audit.assert_called_once()
    audit._admin_credentials.assert_called_once()
    assert metrics.call_count == recorder.return_value.collect.call_count == 2
    assert "synthetic-secret" not in capsys.readouterr().out
