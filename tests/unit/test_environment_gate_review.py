from copy import deepcopy
from dataclasses import replace
from datetime import timedelta

import pytest

from application.environment_gate_review import (
    LATEST_GATE,
    RegisteredPreservationGatePolicy,
    advance_preservation_gate,
    validate_preservation_gate_record,
)
from domain.environment_transition import PreservationObservation, PreservationRequirement
from tests.unit.test_environment_transition import NOW, setup


def case():
    scope, requirements, _ = setup()
    now = NOW
    added = tuple(
        PreservationRequirement(name, name + "-v1", "b" * 64)
        for name in LATEST_GATE
        if name not in {v.capability for v in requirements}
    )
    policy = RegisteredPreservationGatePolicy(
        "write-pause-policy-v1", scope, requirements + added, tuple(LATEST_GATE.items())
    )
    return policy, now


def observations(policy, now, *, through):
    return tuple(
        PreservationObservation(
            policy.scope,
            req,
            side,
            "collected-" + req.capability + "-" + side,
            "registered-collector",
            now,
            now + timedelta(seconds=300),
            "verified",
        )
        for req in policy.requirements
        if dict(policy.due_gates)[req.capability] <= through
        for side in ("source", "target")
    )


def test_early_pass_carries_every_unknown_obligation_without_issuing_execution_rights():
    policy, now = case()
    record = advance_preservation_gate(policy, None, "G0", observations(policy, now, through="G0"), now=now)
    assert (
        record["gate_status"] == "passed"
        and not record["execution_authorized"]
        and not record["migration_completed"]
    )
    assert len(record["obligations"]) == len(policy.requirements)
    data = next(v for v in record["obligations"] if v["capability"] == "persistent_data")
    assert data["due_gate"] == "G8" and data["status"] == "unverified"
    assert data["requires_target_verification"] and data["requires_source_verification"]
    assert validate_preservation_gate_record(policy, record) == record


def test_unknown_authorization_blocks_the_first_gate_and_cannot_be_skipped():
    policy, now = case()
    first = advance_preservation_gate(policy, None, "G0", (), now=now)
    assert first["blocking_obligations"] == ["registered_authorization"]
    with pytest.raises(ValueError, match="skip"):
        advance_preservation_gate(policy, first, "G1", observations(policy, now, through="G1"), now=now)
    retry = advance_preservation_gate(policy, first, "G0", observations(policy, now, through="G0"), now=now)
    assert retry["gate_status"] == "passed" and retry["previous_record_id"] == first["record_id"]


def test_passed_gates_cannot_replay_or_jump_and_have_a_content_bound_parent():
    policy, now = case()
    first = advance_preservation_gate(policy, None, "G0", observations(policy, now, through="G0"), now=now)
    for gate in ("G0", "G2"):
        with pytest.raises(ValueError):
            advance_preservation_gate(policy, first, gate, (), now=now)
    second = advance_preservation_gate(policy, first, "G1", observations(policy, now, through="G1"), now=now)
    changed = deepcopy(second)
    changed["previous_record_id"] = "EGR-" + "c" * 64
    with pytest.raises(ValueError, match="persisted"):
        validate_preservation_gate_record(policy, changed)


def test_verified_status_is_not_inherited_when_current_evidence_has_expired():
    policy, now = case()
    evidence = observations(policy, now, through="G1")
    first = advance_preservation_gate(policy, None, "G0", evidence, now=now)
    later = advance_preservation_gate(policy, first, "G1", evidence, now=now + timedelta(seconds=301))
    assert later["gate_status"] == "blocked" and "registered_authorization" in later["blocking_obligations"]


@pytest.mark.parametrize(
    "capability", ["backup_restore", "identity_access", "transfer_rehearsal", "current_execution_approval"]
)
def test_registered_policy_cannot_defer_protection_or_approval_until_after_effects(capability):
    policy, _ = case()
    with pytest.raises(ValueError, match="floor"):
        replace(
            policy,
            due_gates=tuple((name, "G8" if name == capability else gate) for name, gate in policy.due_gates),
        )


def test_model_proposal_cannot_satisfy_a_hard_gate_or_remove_an_obligation():
    policy, now = case()
    evidence = tuple(replace(v, origin="agent_proposal") for v in observations(policy, now, through="G0"))
    first = advance_preservation_gate(policy, None, "G0", evidence, now=now)
    assert first["gate_status"] == "blocked"
    changed = deepcopy(first)
    changed["obligations"] = []
    with pytest.raises(ValueError):
        validate_preservation_gate_record(policy, changed)
    with pytest.raises(ValueError):
        replace(policy, requirements=policy.requirements[:-1])


def test_every_stage_requires_rehearsal_and_pre_effect_approval_but_does_not_self_authorize():
    policy, now = case()
    previous = None
    for index in range(9):
        gate = "G" + str(index)
        previous = advance_preservation_gate(
            policy, previous, gate, observations(policy, now, through=gate), now=now
        )
        assert previous["gate_status"] == "passed"
        assert previous["execution_authorized"] is False and previous["migration_completed"] is False
    assert previous["carried_obligations"] == []
    with pytest.raises(ValueError):
        advance_preservation_gate(policy, previous, "G8", (), now=now)


def test_plan_policy_or_configuration_change_cannot_reuse_a_previous_gate():
    policy, now = case()
    first = advance_preservation_gate(policy, None, "G0", observations(policy, now, through="G0"), now=now)
    changed = replace(policy, scope=replace(policy.scope, target_configuration_revision="d" * 64))
    with pytest.raises(ValueError):
        advance_preservation_gate(changed, first, "G1", (), now=now)
    with pytest.raises(ValueError):
        advance_preservation_gate(policy, first, "G1", (), now=now - timedelta(seconds=1))


@pytest.mark.parametrize(
    "gate,capability",
    [
        ("G1", "dependency_inventory"),
        ("G2", "source_patch_safety"),
        ("G3", "artifact_identity"),
        ("G4", "functional_scenarios"),
        ("G8", "post_cutover_validation"),
    ],
)
def test_each_phase_has_its_own_required_check_and_cannot_pass_vacuously(gate, capability):
    policy, now = case()
    previous = None
    for index in range(int(gate[1])):
        stage = "G" + str(index)
        previous = advance_preservation_gate(
            policy, previous, stage, observations(policy, now, through=stage), now=now
        )
    supplied = tuple(
        v for v in observations(policy, now, through=gate) if v.requirement.capability != capability
    )
    blocked = advance_preservation_gate(policy, previous, gate, supplied, now=now)
    assert blocked["gate_status"] == "blocked" and capability in blocked["blocking_obligations"]
