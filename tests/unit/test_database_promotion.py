"""Shared-to-dedicated plans must not claim a safe cutover before verification."""

import hashlib
import json
from dataclasses import replace

import pytest

from engine.database_promotion import DatabaseBinding, PromotionTrigger, plan_database_promotion


def _binding(role, instance):
    return DatabaseBinding(
        organization_id="team-a",
        application_id="game-a",
        role=role,
        account_id="111111111111",
        region="ap-northeast-2",
        instance_id=instance,
        database_name="game_a",
        owner_ref="app-game-a",
    )


def _trigger():
    return PromotionTrigger(
        "scheduled_review", "policy-30-days", "observation-123", "2026-10-10T12:00:00+09:00"
    )


def test_plan_is_source_bound_and_every_data_and_traffic_gate_starts_unverified():
    source = _binding("shared_workload", "shared-pool-1")
    target = _binding("dedicated_workload", "game-a-rds")
    plan = plan_database_promotion(
        source, target, _trigger(), source_revision="a" * 64, websocket_sessions=True
    )

    assert (
        plan["plan_id"]
        == plan_database_promotion(
            source, target, _trigger(), source_revision="a" * 64, websocket_sessions=True
        )["plan_id"]
    )
    assert plan["execution_status"] == "unsupported_by_sky"
    assert plan["ready_to_cutover"] is False
    assert plan["approval_required"] is True
    assert plan["cost_estimate"] is None
    assert plan["source_retirement_status"] == "blocked_until_rollback_window_closes"
    assert plan["source_retirement_scope"] == "application_logical_database_only"
    assert plan["shared_instance_policy"] == "retain"
    assert {gate["name"] for gate in plan["required_gates"]} >= {
        "initial_copy_integrity",
        "continuous_sync_caught_up",
        "single_writer_routing",
        "reverse_sync_or_write_freeze",
        "websocket_session_drain",
    }
    assert all(gate["status"] == "unverified" for gate in plan["required_gates"])
    assert all(candidate["status"] == "blocked" for candidate in plan["strategy_candidates"])
    assert "tenant_sticky_routing" in plan["strategy_candidates"][1]["additional_gates"]
    assert "password" not in str(plan).lower()


@pytest.mark.parametrize(
    ("source_role", "target_role", "source_instance", "target_instance"),
    [
        ("sky_state", "dedicated_workload", "state-db", "game-db"),
        ("dedicated_workload", "dedicated_workload", "old-db", "game-db"),
        ("shared_workload", "shared_workload", "old-db", "game-db"),
        ("shared_workload", "dedicated_workload", "same-db", "same-db"),
    ],
)
def test_plan_rejects_wrong_database_role_or_same_instance(
    source_role, target_role, source_instance, target_instance
):
    with pytest.raises(ValueError):
        plan_database_promotion(
            _binding(source_role, source_instance),
            _binding(target_role, target_instance),
            _trigger(),
            source_revision="b" * 64,
        )


def test_plan_rejects_cross_app_and_unrecorded_trigger():
    source = _binding("shared_workload", "shared-pool-1")
    target = DatabaseBinding(
        organization_id="team-a",
        application_id="another-game",
        role="dedicated_workload",
        account_id="111111111111",
        region="ap-northeast-2",
        instance_id="another-rds",
        database_name="another_game",
        owner_ref="app-another-game",
    )
    with pytest.raises(ValueError, match="ownership"):
        plan_database_promotion(source, target, _trigger(), source_revision="c" * 64)
    with pytest.raises(ValueError, match="timezone"):
        PromotionTrigger("scheduled_review", "policy-30-days", "observation-123", "2026-10-10T12:00:00")


def test_plan_identity_cannot_be_reused_across_account_or_session_requirements():
    source = _binding("shared_workload", "shared-pool-1")
    target = _binding("dedicated_workload", "game-a-rds")
    baseline = plan_database_promotion(source, target, _trigger(), source_revision="d" * 64)
    another_account = plan_database_promotion(
        replace(source, account_id="222222222222"),
        replace(target, account_id="222222222222"),
        _trigger(),
        source_revision="d" * 64,
    )
    sessions = plan_database_promotion(
        source, target, _trigger(), source_revision="d" * 64, websocket_sessions=True
    )
    assert len({baseline["plan_id"], another_account["plan_id"], sessions["plan_id"]}) == 3


@pytest.mark.parametrize(
    ("sessions", "account", "revision", "expected_digest"),
    [
        (False, "111111111111", "a", "a27b1884a5f681b1acf3347c8a2c2410a40a63c78597ed3b167a930dc3d8b8d7"),
        (True, "111111111111", "a", "30d6112f49a9338d369f515e219517dbc9a9aa385c61b51b11c07e0e1b1acde3"),
        (False, "222222222222", "d", "3a86593afe3121e9c43a48d885e58e1ea6f3b17c54370569001a70ce3e90b962"),
    ],
)
def test_persisted_legacy_plan_format_and_identity_are_unchanged(
    sessions, account, revision, expected_digest
):
    # Captured before contract extraction. Existing approvals, copy baselines and
    # journal records reference these exact plans; adding fields can invalidate them.
    source = replace(_binding("shared_workload", "shared-pool-1"), account_id=account)
    target = replace(_binding("dedicated_workload", "game-a-rds"), account_id=account)
    result = plan_database_promotion(
        source, target, _trigger(), source_revision=revision * 64, websocket_sessions=sessions
    )
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(encoded).hexdigest() == expected_digest


@pytest.mark.parametrize("change", [{"account_id": "222222222222"}, {"region": "ap-northeast-1"}])
def test_legacy_planner_still_rejects_cross_account_or_region(change):
    with pytest.raises(ValueError, match="Cross-account or cross-region"):
        plan_database_promotion(
            _binding("shared_workload", "shared-pool-1"),
            replace(_binding("dedicated_workload", "game-a-rds"), **change),
            _trigger(),
            source_revision="a" * 64,
        )
