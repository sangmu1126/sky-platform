from dataclasses import asdict, replace
from unittest.mock import Mock

import pytest

from application.environment_cutover import EnvironmentDatabaseCutover
from ports.database_promotion import ReadPreservingWriteFence
from tests.unit.test_database_cutover import Traffic
from tests.unit.test_database_transfer import transfer


class Fence(ReadPreservingWriteFence):
    def __init__(self, binding):
        self.binding, self.enabled = binding, True

    def set_writes(self, enabled, *, guard):
        guard()
        self.enabled = enabled
        return {"writes_enabled": enabled, "reads_preserved": True}


def fixture():
    spec = transfer()
    source, target = Fence(spec.source), Fence(spec.target)
    traffic = Traffic(asdict(spec.source))
    traffic.bindings = [asdict(spec.source), asdict(spec.target)]
    transport = Mock(transfer=spec)
    transport.refresh.side_effect = lambda transfer, **kwargs: {
        **kwargs["expected_destination"],
        "verified_scope": "final_locked_refresh",
    }
    now = [0.0]
    events = []
    flow = EnvironmentDatabaseCutover(
        spec,
        transport,
        source,
        target,
        traffic,
        guard=lambda: None,
        journal=events.append,
        clock=lambda: now[0],
    )
    baseline = {
        "plan_id": spec.document()["plan_id"],
        "source": spec.document()["source"],
        "target": spec.document()["target"],
        "schema_sha256": "a" * 64,
        "tables": [{"table": "scores", "rows": 0, "sha256": "b" * 64}],
        "verified_scope": "locked_table_snapshot_copy",
        "source_retained": True,
        "routing_changed": False,
        "ready_to_cutover": False,
        "requires_final_write_freeze": True,
    }
    return spec, flow, baseline, source, target, traffic, events, now


def test_registered_aws_vm_flow_preserves_single_writer_and_explicit_recovery():
    spec, flow, baseline, source, target, traffic, events, _ = fixture()
    result = flow.promote(spec, baseline)
    assert result["availability_mode"] == "bounded_write_pause" and result["continuous_sync"] is False
    assert result["write_pause_budget_seconds"] == 120 and not source.enabled and target.enabled
    assert traffic.binding == asdict(spec.target) and not traffic.closed
    flow.rollback(spec, result["baseline"])
    assert source.enabled and not target.enabled and traffic.binding == asdict(spec.source)
    assert any(e["stage"] == "reverse_sync" and e["status"] == "observed" for e in events)


def test_time_budget_expiration_keeps_writer_gate_closed_and_stops_new_effects():
    spec, flow, baseline, source, target, traffic, events, now = fixture()
    original = traffic.quiesce

    def expired(binding):
        original(binding)
        now[0] = 121

    traffic.quiesce = expired
    with pytest.raises(RuntimeError, match="budget exceeded"):
        flow.promote(spec, baseline)
    assert traffic.closed and source.enabled and target.enabled
    assert [e["stage"] for e in events] == ["quiesce"]
    flow.sync.transport.refresh.assert_not_called()


def test_journal_failure_prevents_even_the_first_remote_control_call():
    spec, flow, baseline, _, _, traffic, _, _ = fixture()
    flow.journal = Mock(side_effect=OSError("state database unavailable"))
    with pytest.raises(OSError):
        flow.promote(spec, baseline)
    assert not traffic.closed


def test_changed_registration_or_baseline_never_becomes_an_execution():
    spec, flow, baseline, _, _, traffic, events, _ = fixture()
    with pytest.raises(ValueError):
        flow.promote(replace(spec, source_revision="b" * 64), baseline)
    with pytest.raises(ValueError):
        flow.promote(spec, {**baseline, "plan_id": "other"})
    assert not events and not traffic.closed
