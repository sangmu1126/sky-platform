"""Provider plugins use one fixed resource and bounded transfer effect contract."""

from contextlib import contextmanager
from unittest.mock import Mock

import pytest

from application.environment_execution_effect import (
    RegisteredEnvironmentResourceCheck,
    RegisteredEnvironmentTransferEffect,
    RegisteredEnvironmentTransferResources,
)
from tests.unit.test_environment_admission import registered


def resource_check(index, *, evidence=None):
    reference = "ERC-" + format(index, "064x")
    collect = Mock(
        return_value={
            "check_ref": reference,
            "evidence_ref": evidence or "EVIDENCE-" + format(index, "064x"),
        },
        reference=reference,
    )
    return RegisteredEnvironmentResourceCheck(
        reference,
        collect,
    )


def baseline(execution, scope):
    return {
        "plan_id": execution.job.transfer.document()["plan_id"],
        "source": execution.job.transfer.document()["source"],
        "target": execution.job.transfer.document()["target"],
        "schema_sha256": "a" * 64,
        "tables": [{"table": "scores", "rows": 0, "sha256": "b" * 64}],
        "verified_scope": scope,
        "source_retained": True,
        "routing_changed": False,
        "ready_to_cutover": False,
        "requires_final_write_freeze": True,
    }


def test_resource_checks_are_revision_bound_guarded_and_canonical():
    execution = registered()
    checks = (resource_check(1, evidence="Z-evidence"), resource_check(2, evidence="A-evidence"))
    verifier = RegisteredEnvironmentTransferResources(execution, checks)
    guard = Mock()

    assert verifier.reference.startswith("EVR-")
    assert verifier.verify(execution, guard=guard) == {
        "execution_revision": execution.revision,
        "verified": True,
        "evidence_refs": ["A-evidence", "Z-evidence"],
    }
    assert guard.call_count == 4
    for check in checks:
        check.collect.assert_called_once_with(execution, guard=guard)


def test_resource_check_drift_duplicate_evidence_or_changed_execution_is_rejected():
    execution = registered()
    first = resource_check(1, evidence="same-evidence")
    second = resource_check(2, evidence="same-evidence")
    verifier = RegisteredEnvironmentTransferResources(execution, (first, second))
    with pytest.raises(ValueError, match="Distinct"):
        verifier.verify(execution, guard=Mock())
    first.collect.return_value["check_ref"] = "ERC-" + "f" * 64
    with pytest.raises(ValueError, match="Exact registered"):
        RegisteredEnvironmentTransferResources(execution, (first,)).verify(execution, guard=Mock())
    other = registered()
    object.__setattr__(other.job, "id", "other-registration")
    with pytest.raises(ValueError, match="Exact guarded"):
        verifier.verify(other, guard=Mock())

    with pytest.raises(ValueError, match="collector differs"):
        RegisteredEnvironmentResourceCheck(first.reference, Mock(reference="ERC-" + "f" * 64))


def test_resource_check_rechecks_collector_pin_before_guard_or_collection():
    execution = registered()
    check = resource_check(1)
    verifier = RegisteredEnvironmentTransferResources(execution, (check,))
    guard = Mock()
    check.collect.reference = "ERC-" + "f" * 64

    with pytest.raises(ValueError, match="Exact guarded"):
        verifier.verify(execution, guard=guard)

    guard.assert_not_called()
    check.collect.assert_not_called()


def effect_fixture():
    execution = registered()
    transfer = execution.job.transfer
    transport = Mock(transfer=transfer)
    transport.verify_registration.return_value = {
        "plan_id": transfer.document()["plan_id"],
        "registration_verified": True,
        "mutation": False,
    }
    transport.copy.return_value = baseline(execution, "locked_table_snapshot_copy")
    result = {
        "plan_id": transfer.document()["plan_id"],
        "binding": transfer.document()["target"],
        "baseline": baseline(execution, "final_locked_refresh"),
        "single_writer": True,
        "source_retained": True,
        "availability_mode": "bounded_write_pause",
        "continuous_sync": False,
        "operation_elapsed_seconds": 4.5,
        "write_pause_budget_seconds": transfer.policy.write_pause_budget_seconds,
    }
    flow = Mock(transfer=transfer)
    flow.promote.return_value = result

    @contextmanager
    def runtime(selected, *, guard, journal):
        assert selected == execution and callable(guard) and callable(journal)
        yield transport, flow

    runtime.reference = "ETR-" + "c" * 64
    runtime.execution = execution
    return (
        execution,
        RegisteredEnvironmentTransferEffect(execution, "ETR-" + "c" * 64, runtime),
        transport,
        flow,
        result,
    )


def test_effect_performs_only_registered_copy_then_bounded_cutover():
    execution, effect, transport, flow, result = effect_fixture()
    guard, journal = Mock(), Mock()
    assert effect.reference.startswith("EEF-")
    assert effect(execution, guard=guard, journal=journal) == result
    transport.verify_registration.assert_called_once_with(execution.job.transfer, guard=guard)
    transport.copy.assert_called_once_with(execution.job.transfer, guard=guard)
    flow.promote.assert_called_once_with(execution.job.transfer, transport.copy.return_value)
    assert journal.call_args_list[0].args[0] == {"stage": "initial_copy", "status": "intent"}
    assert journal.call_args_list[1].args[0] == {"stage": "initial_copy", "status": "observed"}


@pytest.mark.parametrize("failure", ["runtime", "verification", "copy", "receipt"])
def test_effect_never_accepts_changed_runtime_or_ambiguous_receipt(failure):
    execution, effect, transport, flow, _result = effect_fixture()
    if failure == "runtime":
        transport.transfer = registered().job.transfer
        object.__setattr__(transport.transfer, "source_revision", "f" * 64)
    elif failure == "verification":
        transport.verify_registration.return_value["mutation"] = True
    elif failure == "copy":
        transport.copy.return_value["verified_scope"] = "unknown"
    else:
        flow.promote.return_value["single_writer"] = False
    with pytest.raises(ValueError):
        effect(execution, guard=Mock(), journal=Mock())


@pytest.mark.parametrize(
    "elapsed",
    [-1, True, float("nan"), float("inf"), float("-inf"), 121],
)
def test_effect_requires_finite_elapsed_time_within_write_pause_budget(elapsed):
    execution, effect, _transport, flow, _result = effect_fixture()
    flow.promote.return_value["operation_elapsed_seconds"] = elapsed

    with pytest.raises(ValueError, match="Exact bounded"):
        effect(execution, guard=Mock(), journal=Mock())


@pytest.mark.parametrize("location", ["verification", "initial", "final", "receipt"])
def test_effect_rejects_noncanonical_or_extra_receipt_metadata(location):
    execution, effect, transport, flow, _result = effect_fixture()
    if location == "verification":
        transport.verify_registration.return_value["private_detail"] = "must-not-persist"
    elif location == "initial":
        transport.copy.return_value["private_detail"] = "must-not-persist"
    elif location == "final":
        flow.promote.return_value["baseline"]["private_detail"] = "must-not-persist"
    else:
        flow.promote.return_value["private_detail"] = "must-not-persist"

    with pytest.raises(ValueError, match="Exact"):
        effect(execution, guard=Mock(), journal=Mock())


@pytest.mark.parametrize(
    "change",
    [
        "schema",
        "table",
        "table-container",
        "sequence",
        "sequence-container",
        "table-duplicate",
        "total-rows",
        "sequence-duplicate",
        "sequence-orphan",
    ],
)
def test_effect_requires_bounded_canonical_copy_evidence(change):
    execution, effect, transport, _flow, _result = effect_fixture()
    value = transport.copy.return_value
    if change == "schema":
        value["schema_sha256"] = "latest"
    elif change == "table":
        value["tables"][0]["detail"] = "must-not-persist"
    elif change == "table-container":
        value["tables"] = [None]
    elif change == "sequence":
        value["sequences"] = [{"table": "scores", "column": "id", "next_value": True}]
    elif change == "sequence-container":
        value["sequences"] = [None]
    elif change == "table-duplicate":
        value["tables"] = [
            {"table": "scores", "rows": 0, "sha256": "b" * 64},
            {"table": "scores", "rows": 0, "sha256": "c" * 64},
        ]
    elif change == "total-rows":
        value["tables"] = [
            {"table": "accounts", "rows": 60000, "sha256": "b" * 64},
            {"table": "scores", "rows": 60000, "sha256": "c" * 64},
        ]
    elif change == "sequence-duplicate":
        sequence = {"table": "scores", "column": "id", "next_value": 1}
        value["sequences"] = [sequence, dict(sequence)]
    else:
        value["sequences"] = [{"table": "users", "column": "id", "next_value": 1}]

    with pytest.raises(ValueError, match="Exact registered"):
        effect(execution, guard=Mock(), journal=Mock())


def test_effect_reference_changes_with_runtime_or_execution_revision():
    execution, effect, *_ = effect_fixture()
    implementation = Mock(reference="ETR-" + "d" * 64, execution=execution)
    other_runtime = RegisteredEnvironmentTransferEffect(execution, implementation.reference, implementation)
    assert other_runtime.reference != effect.reference
    changed = registered()
    object.__setattr__(changed.job, "input_sha256", "f" * 64)
    changed_runtime = Mock(reference=effect.runtime_ref, execution=changed)
    changed_effect = RegisteredEnvironmentTransferEffect(changed, effect.runtime_ref, changed_runtime)
    assert changed_effect.reference != effect.reference


def test_effect_rejects_runtime_implementation_with_different_reference():
    execution, effect, *_ = effect_fixture()
    effect.runtime.reference = "ETR-" + "f" * 64
    with pytest.raises(ValueError, match="differs from registered reference"):
        RegisteredEnvironmentTransferEffect(execution, effect.runtime_ref, effect.runtime)


def test_effect_rejects_runtime_bound_to_different_execution():
    execution, effect, *_ = effect_fixture()
    other = registered()
    object.__setattr__(other.job, "id", "other-registration")
    effect.runtime.execution = other
    with pytest.raises(ValueError, match="differs from registered reference"):
        RegisteredEnvironmentTransferEffect(execution, effect.runtime_ref, effect.runtime)


def test_effect_rechecks_runtime_pin_before_execution():
    execution, effect, transport, flow, _result = effect_fixture()
    effect.runtime.reference = "ETR-" + "f" * 64

    with pytest.raises(ValueError, match="Exact guarded"):
        effect(execution, guard=Mock(), journal=Mock())
    transport.verify_registration.assert_not_called()
    flow.promote.assert_not_called()
