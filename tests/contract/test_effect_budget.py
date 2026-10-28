"""Durable reservations on actual disposable PostgreSQL; synthetic operator prices."""

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from adapters.state.effect_budget import EffectBudgetExceeded, EffectBudgetPolicy
from tests.contract.test_operation_store import database as database  # noqa: PLC0414
from tests.contract.test_operation_store import store as store  # noqa: PLC0414


def policy(**changes):
    document = {
        "version": 1,
        "expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
        "source": "synthetic test maximum, not a provider price",
        "limits": {
            scope: {"requests": limit, "build_seconds": limit * 60, "microusd": limit * 100}
            for scope, limit in (("global", 3), ("organization", 2), ("user", 1))
        },
        "effects": {"github_build": {"requests": 1, "build_seconds": 60, "microusd": 100}},
    }
    document.update(changes)
    return EffectBudgetPolicy.from_environment({"SKY_EFFECT_BUDGET_JSON": json.dumps(document)})


def reserve(connection, budget, workspace, key, *, org="team", user="alice", binding=None):
    return budget.reserve(
        connection,
        workspace=workspace,
        effect_key=key,
        organization_id=org,
        user_id=user,
        kind="github_build",
        binding=binding or {"source": "a" * 64},
    )


def test_parallel_global_and_tenant_reservations_do_not_overspend(database):
    budget, workspace = policy(), uuid4().hex

    def attempt(index):
        try:
            with database() as connection:
                return reserve(
                    connection,
                    budget,
                    workspace,
                    "call" + str(index),
                    org="org" + str(index),
                    user="user" + str(index),
                )
        except EffectBudgetExceeded:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(attempt, range(12))) == 3


def test_replay_is_not_a_second_allowance_and_rebinding_fails(database):
    budget, workspace = policy(), uuid4().hex
    with database() as db:
        assert reserve(db, budget, workspace, "same")
    with database() as db:
        assert not reserve(db, budget, workspace, "same")
    with database() as db, pytest.raises(ValueError, match="rebound"):
        reserve(db, budget, workspace, "same", binding={"source": "b" * 64})
    with database() as db, pytest.raises(EffectBudgetExceeded):
        reserve(db, budget, workspace, "different")


def test_all_dimensions_and_organization_scope_are_enforced(database):
    budget, workspace = policy(), uuid4().hex
    for index in range(2):
        with database() as db:
            reserve(db, budget, workspace, str(index), user="user" + str(index))
    with database() as db, pytest.raises(EffectBudgetExceeded):
        reserve(db, budget, workspace, "another", user="new-user")
    # A different organization is still subject to the same global cap.
    with database() as db:
        assert reserve(db, budget, workspace, "other", org="other")


def test_conflicting_policy_or_expired_quote_cannot_reset_counters(database):
    budget, workspace = policy(), uuid4().hex
    with database() as db:
        reserve(db, budget, workspace, "first")
    changed = policy(source="another replica policy")
    with database() as db, pytest.raises(EffectBudgetExceeded, match="changed"):
        reserve(db, changed, workspace, "second", user="bob")
    expired = policy(expires_at=(datetime.now(UTC) - timedelta(seconds=1)).isoformat())
    with database() as db, pytest.raises(EffectBudgetExceeded, match="expired"):
        reserve(db, expired, uuid4().hex, "third")


@pytest.mark.parametrize("metric", ["requests", "build_seconds", "microusd"])
def test_each_resource_dimension_can_independently_stop_execution(database, metric):
    document = json.loads(policy().document)
    document["effects"]["github_build"][metric] = document["limits"]["user"][metric] + 1
    budget = EffectBudgetPolicy.from_environment({"SKY_EFFECT_BUDGET_JSON": json.dumps(document)})
    with database() as db, pytest.raises(EffectBudgetExceeded):
        reserve(db, budget, uuid4().hex, "one")


def test_budget_and_external_intent_commit_or_rollback_together(store, database):
    store.effect_budget = policy()
    command = {"organization_id": "team", "created_by": "alice"}
    first = store.admit("app-one", "deploy", "one", command)
    lease = store.claim(first.id, first.attempt_id, "worker")
    assert store.begin_external(lease, {"kind": "github_build", "source": "a" * 64})
    second = store.admit("app-two", "deploy", "two", command)
    another = store.claim(second.id, second.attempt_id, "worker")
    with pytest.raises(EffectBudgetExceeded):
        store.begin_external(another, {"kind": "github_build", "source": "b" * 64})
    assert not store.get(second.id).external_pending
    with database() as db:
        assert db.execute(
            "SELECT count(*) FROM sky_state.effect_budget_reservations WHERE workspace=%s", (store.workspace,)
        ).fetchone() == (1,)
    # Unknown result keeps its reservation, even after the requesting process exits.
    assert store.get(first.id).external_pending


def test_stale_worker_cannot_reserve_or_record_external_intent(store, database):
    store.effect_budget = policy()
    operation = store.admit("app", "deploy", "one", {"organization_id": "team", "created_by": "alice"})
    lease = store.claim(operation.id, operation.attempt_id, "worker")
    with database() as db:
        db.execute(
            "UPDATE sky_state.operations SET lease_until=clock_timestamp()-interval '1 second' WHERE workspace=%s",
            (store.workspace,),
        )
    assert not store.begin_external(lease, {"kind": "github_build"})
    with database() as db:
        assert db.execute(
            "SELECT count(*) FROM sky_state.effect_budget_reservations WHERE workspace=%s", (store.workspace,)
        ).fetchone() == (0,)


@pytest.mark.parametrize(
    "environment",
    [
        {"SKY_REQUIRE_EFFECT_BUDGETS": "true"},
        {"SKY_REQUIRE_EFFECT_BUDGETS": "TRUE"},
        {"SKY_EFFECT_BUDGET_JSON": '{"version":1,"version":2}'},
    ],
)
def test_missing_or_malformed_required_policy_refuses_configuration(environment):
    with pytest.raises(ValueError):
        EffectBudgetPolicy.from_environment(environment)
