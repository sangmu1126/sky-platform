"""Operation-bound model metering. Provider billing remains the final cost authority."""

import hashlib
import json
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

CURRENT_MODEL_BUDGET = ContextVar("sky_model_budget", default=None)


@dataclass(frozen=True)
class ModelTariff:
    model: str
    max_input_tokens: int
    max_output_tokens: int
    input_microusd_per_million: int
    output_microusd_per_million: int
    expires_at: str
    source: str

    def __post_init__(self):
        if (
            not isinstance(self.model, str)
            or not 1 <= len(self.model) <= 128
            or not isinstance(self.source, str)
            or not 1 <= len(self.source) <= 256
            or any(
                type(v) is not int or not 1 <= v <= 10**9
                for v in (
                    self.max_input_tokens,
                    self.max_output_tokens,
                    self.input_microusd_per_million,
                    self.output_microusd_per_million,
                )
            )
            or datetime.fromisoformat(self.expires_at).tzinfo is None
        ):
            raise ValueError("Trusted expiring model context bound and tariff required")

    def cost(self, incoming, outgoing):
        return (
            incoming * self.input_microusd_per_million + outgoing * self.output_microusd_per_million + 999999
        ) // 1000000

    def check(self):
        if datetime.now(UTC) >= datetime.fromisoformat(self.expires_at):
            raise ValueError("Model tariff/context registration expired")


class OperationModelBudget:
    """Trusted worker creates this with its current lease and operator configuration.

    Reserve the entire registered input context and requested output maximum for
    every HTTP attempt. No estimates derived from prompt text or tokenization.
    Missing/invalid usage or lost responses keep the upper bound and pending
    intent, requiring reconciliation. Observed use never refunds the reservation.
    """

    def __init__(self, store, lease, tariff, guard, *, max_calls=8):
        if (
            store.effect_budget is None
            or not isinstance(tariff, ModelTariff)
            or not callable(guard)
            or type(max_calls) is not int
            or not 1 <= max_calls <= 16
        ):
            raise ValueError("Durable lease-owned bounded model execution required")
        self.store, self.lease, self.tariff, self.guard = store, lease, tariff, guard
        self.max_calls, self.calls = max_calls, 0

    def begin(self, request):
        self.guard()
        self.tariff.check()
        body = json.loads(request.data)
        maximum = body.get("max_output_tokens")
        if (
            request.full_url != "https://api.openai.com/v1/responses"
            or body.get("model") != self.tariff.model
            or type(maximum) is not int
            or not 16 <= maximum <= self.tariff.max_output_tokens
            or any(k in body for k in ("previous_response_id", "conversation", "background", "stream"))
            or len(request.data) > self.tariff.max_input_tokens
            or self.calls >= self.max_calls
        ):
            raise ValueError("Model request exceeds its registered bounded profile")

        def text_only(value):
            if isinstance(value, list):
                return all(text_only(item) for item in value)
            if isinstance(value, dict):
                if value.get("type") in {"input_file", "input_image", "input_audio", "item_reference"}:
                    return False
                if any(k in value for k in ("file_url", "image_url", "file_id", "file_data")):
                    return False
                return all(text_only(item) for item in value.values())
            return True

        if not text_only(body.get("input")):
            raise ValueError("Metered source analysis cannot fetch remote files or images")
        # Networked provider tools are not part of a source-analysis budget.
        if any(
            not isinstance(tool, dict) or tool.get("type") != "function" for tool in body.get("tools", [])
        ):
            raise ValueError("Only local structured function proposals are allowed")
        policy = json.loads(self.store.effect_budget.document)
        reserved = policy["effects"].get("model_request", {})
        required = {
            "requests": 1,
            "input_tokens": self.tariff.max_input_tokens,
            "output_tokens": maximum,
            "microusd": self.tariff.cost(self.tariff.max_input_tokens, maximum),
        }
        if (
            not set(required) <= set(reserved)
            or any(reserved[k] < v for k, v in required.items())
            or any(reserved[k] != 0 for k in set(reserved) - set(required))
        ):
            raise ValueError("Model reservation does not cover its full registered maximum")
        intent = {
            "kind": "model_request",
            "max_calls": self.max_calls,
            "request_digest": hashlib.sha256(request.data).hexdigest(),
            "model": self.tariff.model,
            "call_id": uuid4().hex,
            "max_input_tokens": self.tariff.max_input_tokens,
            "max_output_tokens": maximum,
            "tariff_source": self.tariff.source,
            "tariff_expiry": self.tariff.expires_at,
        }
        if not self.store.begin_external(self.lease, intent):
            raise ValueError("Model execution lease is no longer current")
        self.guard()
        self.calls += 1
        return intent

    def complete(self, intent, raw):
        self.guard()
        body = json.loads(raw)
        usage = body.get("usage")
        if (
            not isinstance(body.get("id"), str)
            or not body["id"].startswith("resp_")
            or not isinstance(usage, dict)
            or any(type(usage.get(k)) is not int or usage[k] < 0 for k in ("input_tokens", "output_tokens"))
            or usage["input_tokens"] > intent["max_input_tokens"]
            or usage["output_tokens"] > intent["max_output_tokens"]
        ):
            raise ValueError("Provider usage missing or outside reservation; reconciliation required")
        reserved = json.loads(self.store.effect_budget.document)["effects"]["model_request"]
        actual = {
            **dict.fromkeys(reserved, 0),
            "requests": 1,
            "input_tokens": usage["input_tokens"],
            "output_tokens": usage["output_tokens"],
            "microusd": self.tariff.cost(usage["input_tokens"], usage["output_tokens"]),
        }
        evidence = hashlib.sha256(raw).hexdigest()
        self.store.settle_external_usage(self.lease, actual, evidence)
        operation = self.store.get(self.lease.operation_id)
        if not self.store.observe_external(
            self.lease,
            {
                "response_digest": evidence,
                "usage": actual,
                "cost_basis": "operator_tariff_upper_estimate_not_final_invoice",
                "reservation_released": False,
            },
            operation.checkpoint,
        ):
            raise ValueError("Model lease expired after response; reconciliation required")
        self.guard()

    def rejection(self, intent, status):
        # A classified HTTP rejection was received, but do not infer it was free.
        self.guard()
        operation = self.store.get(self.lease.operation_id)
        if not self.store.observe_external(
            self.lease,
            {
                "request_digest": intent["request_digest"],
                "http_status": status,
                "reservation_released": False,
                "usage_unknown": True,
            },
            operation.checkpoint,
        ):
            raise ValueError("Model rejection ownership lost")


@contextmanager
def metered_model(budget):
    if not isinstance(budget, OperationModelBudget) or CURRENT_MODEL_BUDGET.get() is not None:
        raise ValueError("One trusted model budget per execution context required")
    token = CURRENT_MODEL_BUDGET.set(budget)
    try:
        yield
    finally:
        CURRENT_MODEL_BUDGET.reset(token)
