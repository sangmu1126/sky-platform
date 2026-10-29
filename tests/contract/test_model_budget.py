"""Real PostgreSQL reservations, synthetic HTTP replies; never calls OpenAI."""

import json
import urllib.request
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock, patch

import pytest

from adapters.ai.model_budget import ModelTariff, OperationModelBudget, metered_model
from adapters.ai.openai_http import read_response
from adapters.state.effect_budget import EffectBudgetPolicy
from tests.contract.test_operation_store import database as database  # noqa: PLC0414
from tests.contract.test_operation_store import store as store  # noqa: PLC0414


def model_scope(store):
    maximum = {"requests": 1, "input_tokens": 1024, "output_tokens": 256, "microusd": 1280}
    raw = {
        "version": 2,
        "expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
        "source": "synthetic tariff, not provider pricing",
        "limits": {
            k: {a: v * 4 for a, v in maximum.items()}
            for k in ("global", "organization", "user", "application")
        },
        "effects": {"model_request": maximum},
    }
    store.effect_budget = EffectBudgetPolicy.from_environment({"SKY_EFFECT_BUDGET_JSON": json.dumps(raw)})
    operation = store.admit(
        "demo", "deploy", "model-once", {"organization_id": "team", "created_by": "alice"}
    )
    lease = store.claim(operation.id, operation.attempt_id, "worker")
    tariff = ModelTariff("registered-model", 1024, 256, 1000000, 1000000, raw["expires_at"], raw["source"])
    budget = OperationModelBudget(store, lease, tariff, lambda: None, max_calls=1)
    request = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(
            {"model": "registered-model", "max_output_tokens": 256, "input": "normal source analysis"}
        ).encode(),
        method="POST",
    )
    return budget, request, operation


def test_real_usage_record_retains_upper_reservation_and_limits_repairs(store, database, monkeypatch):
    budget, request, operation = model_scope(store)
    monkeypatch.setenv("SKY_REQUIRE_EFFECT_BUDGETS", "true")
    raw = json.dumps(
        {"id": "resp_synthetic", "usage": {"input_tokens": 10, "output_tokens": 20}, "output": []}
    ).encode()
    response = Mock()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.read.return_value = raw
    with patch("urllib.request.build_opener") as opener, metered_model(budget):
        opener.return_value.open.return_value = response
        assert read_response(request) == raw
        with pytest.raises(ValueError, match="profile"):
            read_response(request)
        assert opener.return_value.open.call_count == 1
    assert not store.get(operation.id).external_pending
    with database() as db:
        reserved, actual = db.execute(
            """SELECT r.reserved,s.actual FROM sky_state.effect_budget_reservations r
            JOIN sky_state.effect_budget_settlements s USING(workspace,effect_key) WHERE r.workspace=%s""",
            (store.workspace,),
        ).fetchone()
    assert reserved["microusd"] == 1280 and actual["microusd"] == 30
    # A new process/context cannot reset the per-operation repair counter.
    another = OperationModelBudget(store, budget.lease, budget.tariff, lambda: None, max_calls=1)
    with pytest.raises(ValueError, match="exhausted"):
        another.begin(request)


def test_lost_model_response_stays_pending_with_full_budget(store, database, monkeypatch):
    budget, request, operation = model_scope(store)
    monkeypatch.setenv("SKY_REQUIRE_EFFECT_BUDGETS", "true")
    with patch("urllib.request.build_opener") as opener, metered_model(budget):
        opener.return_value.open.side_effect = OSError("connection interrupted")
        with pytest.raises(OSError):
            read_response(request)
    assert store.get(operation.id).external_pending
    with database() as db:
        assert db.execute(
            "SELECT count(*) FROM sky_state.effect_budget_settlements WHERE workspace=%s", (store.workspace,)
        ).fetchone() == (0,)
    with pytest.raises(ValueError, match="observation"):
        OperationModelBudget(store, budget.lease, budget.tariff, lambda: None).begin(request)


def test_remote_file_or_unknown_model_is_rejected_before_reservation(store, monkeypatch):
    budget, request, operation = model_scope(store)
    monkeypatch.setenv("SKY_REQUIRE_EFFECT_BUDGETS", "true")
    body = json.loads(request.data)
    body["input"] = [{"type": "input_file", "file_url": "https://untrusted.invalid/file"}]
    request.data = json.dumps(body).encode()
    with (
        patch("urllib.request.build_opener") as opener,
        metered_model(budget),
        pytest.raises(ValueError, match="fetch"),
    ):
        read_response(request)
    opener.return_value.open.assert_not_called()
    assert not store.get(operation.id).external_pending
