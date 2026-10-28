from copy import deepcopy
from unittest.mock import Mock

import pytest

from adapters.database.read_benchmark import RegisteredPostgresPromotionBenchmark
from tests.unit.test_promotion_performance import windows


def test_registered_connectors_and_durable_sink_are_required_for_worker_measurement():
    before, after = windows()
    before["image_digest"] = after["image_digest"] = None
    plan = {
        "source": before["binding"],
        "target": after["binding"],
        "source_revision": before["source_revision"],
    }
    sink = Mock(side_effect=lambda ref, _window, _raw: ref)
    observer = RegisteredPostgresPromotionBenchmark(
        plan,
        Mock(),
        Mock(),
        "SELECT 1",
        query_id="bounded-query",
        evidence_prefix="evidence:owned/operation",
        evidence_sink=sink,
    )
    before["evidence_ref"] = "evidence:owned/operation/before"
    after["evidence_ref"] = "evidence:owned/operation/after"
    observer.collectors = [Mock(run=Mock(return_value=before)), Mock(run=Mock(return_value=after))]
    guard = Mock()
    assert observer.measure(plan, plan["source"], guard=guard) == before
    assert observer.measure(plan, plan["target"], guard=guard) == after
    assert sink.call_count == 2 and guard.call_count == 6
    changed = deepcopy(plan)
    changed["source_revision"] = "e" * 64
    with pytest.raises(ValueError):
        observer.measure(changed, plan["source"], guard=guard)
    assert sink.call_count == 2
    sink.return_value = None
    sink.side_effect = None
    with pytest.raises(ValueError, match="not durably retained"):
        observer.measure(plan, plan["source"], guard=guard)


def test_missing_evidence_sink_never_builds_a_benchmark():
    before, after = windows()
    with pytest.raises(ValueError):
        RegisteredPostgresPromotionBenchmark(
            {"source": before["binding"], "target": after["binding"]},
            Mock(),
            Mock(),
            "SELECT 1",
            query_id="query",
            evidence_prefix="evidence:owned",
            evidence_sink=None,
        )
