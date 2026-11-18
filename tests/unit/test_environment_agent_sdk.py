"""Real SDK offline contracts with a labelled fake Model; no real AI evaluation."""

import asyncio
import json
from threading import Event

import pytest

pytest.importorskip("agents")
from agents import RunContextWrapper, Runner
from agents.exceptions import MaxTurnsExceeded
from agents.items import ModelResponse
from agents.models.interface import Model
from agents.usage import Usage
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText

from adapters.ai.environment_agent_sdk import (
    build_investigation_agent,
    investigation_run_config,
    run_registered_investigation,
)
from application.environment_agent_tools import TOOL_FIELDS
from tests.unit.test_environment_agent_tools import case


class FakeModel(Model):
    """Deterministic tool-call script, not model-generated reasoning."""

    def __init__(self, repeat=False):
        self.calls, self.inputs, self.repeat = 0, [], repeat

    async def get_response(self, system_instructions, input, *args, **kwargs):
        self.calls += 1
        self.inputs.append(input)
        if self.calls == 1 or self.repeat:
            output = [
                ResponseFunctionToolCall(
                    type="function_call",
                    id="fc" + str(self.calls),
                    call_id="call" + str(self.calls),
                    name="get_system_inventory",
                    arguments="{}",
                    status="completed",
                )
            ]
        else:
            output = [
                ResponseOutputMessage(
                    type="message",
                    id="m1",
                    role="assistant",
                    status="completed",
                    content=[
                        ResponseOutputText(
                            type="output_text", text="Needs preservation review.", annotations=[]
                        )
                    ],
                )
            ]
        return ModelResponse(
            output=output,
            usage=Usage(requests=1, input_tokens=1, output_tokens=1, total_tokens=2),
            response_id="fake-" + str(self.calls),
        )

    async def stream_response(self, *args, **kwargs):
        if False:
            yield None
        raise NotImplementedError("No streaming model in offline contract")


def test_actual_sdk_loop_uses_local_context_and_keeps_it_out_of_model_input(monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("Offline SDK contract attempted network")

    monkeypatch.setattr("socket.socket.connect", no_network)
    tools, handler, _, _, _ = case()
    tools._private_canary = "must-never-enter-model-context"
    model = FakeModel()
    agent = build_investigation_agent(model=model)
    result = asyncio.run(
        Runner.run(
            agent,
            "Inspect the registered application.",
            context=tools,
            max_turns=3,
            run_config=investigation_run_config(),
        )
    )
    assert (
        result.final_output == "Needs preservation review." and model.calls == 2 and handler.call_count == 1
    )
    assert "must-never-enter-model-context" not in repr(model.inputs)
    assert "target_unverified" in repr(model.inputs)
    assert {tool.name for tool in agent.tools} == set(TOOL_FIELDS)
    assert not any(tool.name in {"shell", "sql", "deploy", "aws_cli", "fetch_url"} for tool in agent.tools)
    config = investigation_run_config()
    assert config.tracing_disabled and config.trace_include_sensitive_data is False


def test_actual_sdk_turn_limit_ends_a_repeating_tool_loop_without_a_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    tools, handler, _, _, _ = case()
    model = FakeModel(repeat=True)
    with pytest.raises(MaxTurnsExceeded):
        asyncio.run(
            Runner.run(
                build_investigation_agent(model=model),
                "Inspect.",
                context=tools,
                max_turns=2,
                run_config=investigation_run_config(),
            )
        )
    assert model.calls == 2 and handler.call_count == 2


def test_sdk_tool_rejects_actor_injection_and_masks_handler_error():
    tools, handler, _, _, _ = case()
    agent = build_investigation_agent(model=FakeModel())
    tool = next(v for v in agent.tools if v.name == "get_system_inventory")
    wrapper = RunContextWrapper(context=tools)
    denied = json.loads(asyncio.run(tool.on_invoke_tool(wrapper, '{"account_id":"other"}')))
    assert denied["status"] == "blocked" and not denied["execution_authorized"]
    handler.assert_not_called()
    handler.side_effect = RuntimeError("never-expose-source-or-secret")
    denied = asyncio.run(tool.on_invoke_tool(wrapper, "{}"))
    assert "never-expose" not in denied and tools.halted.is_set()


def test_cancellation_halts_context_before_late_handler_result_can_be_published():
    tools, handler, _, _, _ = case()
    active, finish = Event(), Event()
    receipt = handler.return_value

    def slow(*_args):
        active.set()
        assert finish.wait(2)
        return receipt

    handler.side_effect = slow
    tool = build_investigation_agent(model=FakeModel()).tools[0]

    async def scenario():
        pending = asyncio.create_task(tool.on_invoke_tool(RunContextWrapper(context=tools), "{}"))
        try:
            assert await asyncio.to_thread(active.wait, 1)
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
            assert tools.halted.is_set()
        finally:
            finish.set()

    asyncio.run(scenario())
    assert handler.call_count == 1


def test_bounded_runner_does_not_promote_model_text_to_execution_evidence(monkeypatch):
    monkeypatch.setattr("socket.socket.connect", lambda *_: pytest.fail("Offline model must not use network"))
    tools, _, _, _, _ = case()
    result = asyncio.run(run_registered_investigation(tools, model=FakeModel()))
    assert result == {"status": "investigation_finished", "execution_authorized": False}
    assert tools.halted.is_set() and "final_output" not in result


def test_bounded_runner_halts_repeating_tools_at_turn_limit():
    tools, handler, _, _, _ = case()
    result = asyncio.run(run_registered_investigation(tools, model=FakeModel(repeat=True), max_turns=2))
    assert result == {"status": "budget_exhausted", "execution_authorized": False}
    assert tools.halted.is_set() and handler.call_count == 2


def test_bounded_runner_times_out_even_when_model_calls_no_tools():
    class SlowModel(FakeModel):
        async def get_response(self, *args, **kwargs):
            await asyncio.sleep(5)
            raise AssertionError("Model should have been cancelled")

    tools, handler, _, _, _ = case()
    result = asyncio.run(run_registered_investigation(tools, model=SlowModel(), timeout_seconds=1))
    assert result == {"status": "budget_exhausted", "execution_authorized": False}
    assert tools.halted.is_set()
    handler.assert_not_called()


def test_bounded_runner_redacts_model_failure_and_never_retries():
    class FailingModel(FakeModel):
        async def get_response(self, *args, **kwargs):
            self.calls += 1
            raise RuntimeError("source-secret-provider-canary")

    tools, _, _, _, _ = case()
    model = FailingModel()
    result = asyncio.run(run_registered_investigation(tools, model=model))
    assert result == {"status": "blocked", "execution_authorized": False}
    assert model.calls == 1 and tools.halted.is_set() and "canary" not in json.dumps(result)
