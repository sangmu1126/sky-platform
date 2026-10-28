from unittest.mock import Mock

import pytest

from adapters.database.rest_gated_traffic import RestGatedBlueGreenTraffic


def fixture():
    source = {"database": "source"}
    target = {"database": "target"}
    gate = Mock(bindings=[source, target])
    router = Mock()
    router.current.return_value = source

    def switch(left, right):
        assert router.current() == left
        router.current.return_value = right
        return {"binding": right}

    router.switch.side_effect = switch
    runtime = Mock(
        side_effect=lambda b: {
            "database": {"binding": b},
            "url": "https://origin",
            "verification": {"http": "verified"},
        }
    )
    flow = RestGatedBlueGreenTraffic(
        source, target, gate, router, runtime, guard=Mock(), stable_url="https://stable"
    )
    return flow, gate, router, runtime, source, target


def test_requires_closed_gate_and_real_probe_before_writes_and_publication():
    flow, gate, _router, _runtime, source, target = fixture()
    with pytest.raises(ValueError):
        flow.activate(source, target)
    flow.quiesce(source)
    gate.set_active.assert_called_once_with(None)
    flow.activate(source, target)
    with pytest.raises(ValueError):
        flow.resume(target)
    flow.probe(target)
    flow.resume(target)
    assert gate.set_active.call_args.args == (target,)
    result = flow.published_runtime(target)
    assert result["url"] == "https://stable"
    assert result["origin_url"] == "https://origin"
    assert result["verification"]["stable_route"] == "verified"


def test_uncertain_gate_update_is_not_automatically_replayed():
    flow, gate, _, _, source, _ = fixture()
    gate.set_active.side_effect = TimeoutError("Unknown external result")
    with pytest.raises(TimeoutError):
        flow.quiesce(source)
    with pytest.raises(ValueError):
        flow.quiesce(source)
    assert gate.set_active.call_count == 1


def test_wrong_runtime_database_keeps_writes_closed():
    flow, gate, router, runtime, source, target = fixture()
    flow.quiesce(source)
    runtime.return_value = {}
    runtime.side_effect = lambda _: {"database": {"binding": source}}
    with pytest.raises(ValueError):
        flow.activate(source, target)
    router.switch.assert_not_called()
    assert flow.closed and flow.uncertain
    with pytest.raises(ValueError):
        flow.resume(target)
    gate.set_active.assert_called_once_with(None)


def test_changed_route_prevents_reopening_old_writer():
    flow, gate, router, _runtime, source, target = fixture()
    flow.quiesce(source)
    flow.activate(source, target)
    flow.probe(target)
    router.current.return_value = source
    with pytest.raises(ValueError):
        flow.resume(target)
    gate.set_active.assert_called_once_with(None)
