"""Reviewed workers accept only fresh DB ownership and current source route evidence."""

from dataclasses import replace
from datetime import timedelta
from unittest.mock import Mock

import pytest

from adapters.database.environment_execution_resources import (
    RegisteredDatabaseExecutionResourceCheck,
    RegisteredRouteExecutionResourceCheck,
    RegisteredRuntimeExecutionResourceCheck,
    registered_environment_transfer_resource_checks,
)
from application.environment_execution_effect import RegisteredEnvironmentTransferResources
from domain.database_inventory import DatabaseResourceEvidence
from tests.unit.test_database_transfer import NOW, adapter
from tests.unit.test_environment_admission import registered
from tests.unit.test_environment_execution_runtime import runtime_fixture
from tests.unit.test_environment_router import fixture as router_fixture


def database_check(tmp_path, side=0):
    execution = registered()
    _transfer, _transport, endpoints, _verifiers, _connects = adapter(tmp_path)
    endpoint = endpoints[side]
    verifier = Mock()
    verifier.verify.return_value = DatabaseResourceEvidence(
        endpoint.inventory.resource,
        ("AWS-" if side == 0 else "VM-") + "a" * 64,
        NOW,
        endpoint.inventory.hostname,
        endpoint.inventory.port,
    )
    check = RegisteredDatabaseExecutionResourceCheck(execution, endpoint, verifier, clock=lambda: NOW)
    return execution, endpoint, verifier, check


def test_database_check_binds_execution_endpoint_transport_and_fresh_evidence(tmp_path):
    execution, endpoint, verifier, check = database_check(tmp_path)
    guard = Mock()

    assert check.reference.startswith("ERC-")
    assert check.collect(execution, guard=guard) == {
        "check_ref": check.reference,
        "evidence_ref": "AWS-" + "a" * 64,
    }
    verifier.verify.assert_called_once_with(endpoint.inventory.resource)
    assert guard.call_count == 2

    changed = replace(endpoint, connect_port=35432, connect_hostaddr="127.0.0.1")
    changed_check = RegisteredDatabaseExecutionResourceCheck(execution, changed, verifier, clock=lambda: NOW)
    assert changed_check.reference != check.reference


@pytest.mark.parametrize("change", ["stale", "future", "placement", "hostname", "clock"])
def test_database_check_rejects_changed_or_noncurrent_ownership(tmp_path, change):
    execution, endpoint, verifier, check = database_check(tmp_path)
    proof = verifier.verify.return_value
    if change == "stale":
        verifier.verify.return_value = replace(proof, observed_at=NOW - timedelta(seconds=60))
    elif change == "future":
        verifier.verify.return_value = replace(proof, observed_at=NOW + timedelta(seconds=1))
    elif change == "placement":
        verifier.verify.return_value = replace(proof, placement=execution.job.transfer.target)
    elif change == "hostname":
        verifier.verify.return_value = replace(proof, server_hostname="changed.test")
    else:
        check.clock = lambda: NOW.replace(tzinfo=None)
    with pytest.raises(ValueError, match="Current registered"):
        check.collect(execution, guard=Mock())
    assert endpoint.inventory.sslrootcert not in check.reference


def route_check():
    execution = registered()
    router, state, _container = router_fixture()

    def factory(selected, *, guard):
        assert selected == execution
        router.guard = guard
        return router

    check = RegisteredRouteExecutionResourceCheck(execution, router.registration, factory)
    return execution, router, state, check


def test_route_check_requires_guard_bound_router_and_actual_source_read():
    execution, router, _state, check = route_check()
    guard = Mock()
    result = check.collect(execution, guard=guard)
    assert result["check_ref"] == check.reference
    assert result["evidence_ref"].startswith("ROUTE-")
    assert router.verify_runtime.call_count == 2
    assert guard.call_count >= 2


def test_route_check_rejects_target_route_or_factory_drift():
    execution, router, state, check = route_check()
    state["configuration"] = router.registration.configuration(execution.job.transfer.document()["target"])
    state["binding"] = execution.job.transfer.document()["target"]
    with pytest.raises(ValueError, match="Unexpected active route"):
        check.collect(execution, guard=Mock())

    check.router_factory = lambda *_args, **_kwargs: router
    router.guard = lambda: None
    with pytest.raises(ValueError, match="Guard-bound"):
        check.collect(execution, guard=Mock())


def test_canonical_bundle_feeds_fixed_evr_aggregator(tmp_path):
    execution = registered()
    _transfer, _transport, endpoints, _verifiers, _connects = adapter(tmp_path)
    verifiers = []
    for index, endpoint in enumerate(endpoints):
        verifier = Mock()
        verifier.verify.return_value = DatabaseResourceEvidence(
            endpoint.inventory.resource,
            ("AWS-" if index == 0 else "VM-") + format(index, "064x"),
            NOW,
            endpoint.inventory.hostname,
            endpoint.inventory.port,
        )
        verifiers.append(verifier)
    router, _state, _container = router_fixture()

    def router_factory(_execution, *, guard):
        router.guard = guard
        return router

    checks = registered_environment_transfer_resource_checks(
        execution,
        source_endpoint=endpoints[0],
        source_verifier=verifiers[0],
        target_endpoint=endpoints[1],
        target_verifier=verifiers[1],
        router_registration=router.registration,
        router_factory=router_factory,
        clock=lambda: NOW,
    )
    assert checks == tuple(sorted(checks, key=lambda value: value.reference))
    receipt = RegisteredEnvironmentTransferResources(execution, checks).verify(execution, guard=Mock())
    assert receipt["verified"] is True
    assert len(receipt["evidence_refs"]) == 3


def runtime_check(tmp_path, *, mutation=False):
    execution, _resolver, runtime = runtime_fixture(tmp_path)
    compose = runtime.composer

    def read_only_composer(*args, **kwargs):
        transport, flow = compose(*args, **kwargs)
        plan_id = execution.job.transfer.document()["plan_id"]
        if mutation:
            transport.verify_registration = lambda *_args, **_kwargs: flow.journal(
                {"stage": "forbidden", "status": "intent"}
            )
        else:
            transport.verify_registration = Mock(
                return_value={
                    "plan_id": plan_id,
                    "registration_verified": True,
                    "mutation": False,
                }
            )
        binding = execution.job.transfer.document()["source"]
        flow.traffic.router.probe = Mock(
            return_value={"binding": binding, "verified_scope": "routed_https_database_read"}
        )
        return transport, flow

    runtime.composer = read_only_composer
    return execution, runtime, RegisteredRuntimeExecutionResourceCheck(execution, runtime.reference, runtime)


def test_runtime_check_opens_pinned_materials_for_read_only_database_and_route_proof(tmp_path):
    execution, runtime, check = runtime_check(tmp_path)
    guard = Mock()
    receipt = check.collect(execution, guard=guard)
    assert check.reference.startswith("ERC-")
    assert receipt["check_ref"] == check.reference
    assert receipt["evidence_ref"].startswith("ENVRT-")
    assert len([event for event in runtime.resolver.events if event[0] == "open"]) == 5
    assert len([event for event in runtime.resolver.events if event[0] == "close"]) == 5
    resources = RegisteredEnvironmentTransferResources(execution, (check.check(),))
    assert resources.verify(execution, guard=Mock())["verified"] is True


def test_runtime_resource_check_cannot_record_or_cross_external_effect_intent(tmp_path):
    execution, _runtime, check = runtime_check(tmp_path, mutation=True)
    with pytest.raises(RuntimeError, match="cannot record"):
        check.collect(execution, guard=Mock())
