"""Only registered dependency collectors can satisfy the G1 observation."""

from dataclasses import replace
from unittest.mock import Mock

import pytest

from application.environment_dependency_inventory import (
    RegisteredDependencyInventoryCollector,
    dependency_inventory_requirement,
)
from application.environment_gate_review import RegisteredPreservationGatePolicy, advance_preservation_gate
from ports.environment_transition import PreservationCollectionUnavailable
from ports.workload_inventory import WorkloadInventoryUnavailable
from tests.unit.test_environment_gate_review import case, observations
from tests.unit.test_environment_transition import NOW
from tests.unit.test_workload_inventory import registration, snapshot


def collector():
    registered = registration()
    source = Mock(collect=Mock(return_value=snapshot(registered, "source")))
    target = Mock(collect=Mock(return_value=snapshot(registered, "target")))
    published = {}

    class Publisher:
        def publish(self, report):
            published[report["report_id"]] = report
            return report["report_id"]

    value = RegisteredDependencyInventoryCollector(
        registered,
        source,
        target,
        Publisher(),
        verifier_ref="registered-dependency-collector",
        clock=lambda: NOW,
    )
    return value, registered, source, target, published


def test_collector_publishes_full_report_and_returns_two_bound_observations():
    value, registered, source, target, published = collector()
    requirement = dependency_inventory_requirement(registered)
    result = value.collect(registered.scope, (requirement,))
    assert [item.endpoint for item in result] == ["source", "target"]
    assert all(item.requirement == requirement and item.status == "verified" for item in result)
    assert len(published) == 1 and result[0].evidence_ref in published
    source.collect.assert_called_once_with(registered, "source")
    target.collect.assert_called_once_with(registered, "target")


def test_actual_collector_observations_can_satisfy_g1_without_self_authorizing():
    value, registered, *_ = collector()
    requirement = dependency_inventory_requirement(registered)
    policy, _ = case()
    requirements = tuple(
        requirement if item.capability == "dependency_inventory" else item for item in policy.requirements
    )
    policy = RegisteredPreservationGatePolicy(
        policy.policy_ref,
        registered.scope,
        requirements,
        policy.due_gates,
    )
    actual = value.collect(registered.scope, (requirement,))
    general = tuple(
        item
        for item in observations(policy, NOW, through="G1")
        if item.requirement.capability != "dependency_inventory"
    )
    first = advance_preservation_gate(policy, None, "G0", (*general, *actual), now=NOW)
    second = advance_preservation_gate(policy, first, "G1", (*general, *actual), now=NOW)
    assert second["gate_status"] == "passed"
    assert not second["execution_authorized"] and "source_patch_safety" in second["carried_obligations"]


def test_scope_mismatch_and_reader_failure_never_publish_positive_evidence():
    value, registered, source, _target, published = collector()
    requirement = dependency_inventory_requirement(registered)
    with pytest.raises(ValueError, match="scope differs"):
        value.collect(replace(registered.scope, application_id="other"), (requirement,))
    source.collect.side_effect = WorkloadInventoryUnavailable("token=CANARY")
    with pytest.raises(PreservationCollectionUnavailable) as error:
        value.collect(registered.scope, (requirement,))
    assert "CANARY" not in str(error.value) and not published
