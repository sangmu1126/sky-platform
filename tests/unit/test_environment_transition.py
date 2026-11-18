"""Environment changes preserve outcomes, never inherit approval from AI claims."""

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from domain.environment_transition import (
    BASELINE_CAPABILITIES,
    PreservationObservation,
    PreservationRequirement,
    TransitionScope,
)
from engine.environment_transition import assess_environment_transition

NOW = datetime(2026, 10, 30, 12, tzinfo=UTC)


def setup():
    scope = TransitionScope("org", "app", "aws-prod", "vm-target", "a" * 64, "b" * 64, "c" * 64)
    requirements = tuple(
        PreservationRequirement(key, "criterion-" + key, "d" * 64) for key in BASELINE_CAPABILITIES
    )
    observations = tuple(
        PreservationObservation(
            scope,
            requirement,
            endpoint,
            endpoint + "-" + requirement.capability,
            "registered-" + endpoint + "-verifier",
            NOW - timedelta(seconds=10),
            NOW + timedelta(seconds=60),
            "verified",
        )
        for requirement in requirements
        for endpoint in ("source", "target")
    )
    return scope, requirements, observations


def assess(scope=None, requirements=None, observations=None, **kwargs):
    default_scope, default_requirements, default_observations = setup()
    return assess_environment_transition(
        scope or default_scope,
        default_requirements if requirements is None else requirements,
        default_observations if observations is None else observations,
        now=kwargs.pop("now", NOW),
        **kwargs,
    )


def test_verified_outcomes_do_not_authorize_execution_or_claim_no_downtime():
    report = assess()
    assert report["status"] == "verified"
    assert report["unresolved_capabilities"] == []
    assert report["execution_authorized"] is False
    assert report["ready_to_cutover"] is False
    assert report["availability_claim"] == "not_assessed"
    assert report["approval_scope"] == "environment_preservation_review_only"
    assert json.loads(json.dumps(report)) == report
    # Different implementation identities can satisfy the same outcome criterion.
    assert report["observations"][0]["verifier_ref"] != report["observations"][1]["verifier_ref"]


def test_missing_entire_inventory_preserves_every_obligation_as_unverified():
    report = assess(observations=())
    assert report["status"] == "blocked"
    assert set(report["unresolved_capabilities"]) == set(BASELINE_CAPABILITIES)
    assert all(check["status"] == "unverified" for check in report["checks"])


@pytest.mark.parametrize("endpoint", ["source", "target"])
def test_missing_either_endpoint_is_not_equivalence(endpoint):
    scope, requirements, observations = setup()
    report = assess(scope, requirements, tuple(item for item in observations if item.endpoint != endpoint))
    assert report["status"] == "blocked"
    assert all(check["status"] == "unverified" for check in report["checks"])


@pytest.mark.parametrize(
    ("changes", "status", "reason"),
    [
        ({"status": "failed"}, "failed", "criterion_failed"),
        ({"status": "unknown"}, "unverified", "collector_could_not_verify"),
        ({"origin": "agent_proposal"}, "unverified", "proposal_is_not_verification"),
        ({"observed_at": NOW + timedelta(seconds=1)}, "unverified", "future_evidence"),
        ({"expires_at": NOW}, "unverified", "expired_evidence"),
        ({"observed_at": NOW - timedelta(seconds=300)}, "unverified", "expired_evidence"),
    ],
)
def test_failed_unknown_ai_and_stale_results_are_not_silently_promoted(changes, status, reason):
    scope, requirements, observations = setup()
    changed = replace(observations[0], **changes)
    report = assess(scope, requirements, (changed, *observations[1:]))
    check = next(item for item in report["checks"] if item["capability"] == changed.requirement.capability)
    assert report["status"] == "blocked"
    assert check["status"] == status
    assert check["endpoints"]["source"]["reason"] == reason


@pytest.mark.parametrize("field", ["organization_id", "application_id", "target_environment_ref"])
def test_observation_cannot_cross_tenant_app_or_environment(field):
    scope, requirements, observations = setup()
    changed = replace(observations[0], scope=replace(scope, **{field: "other"}))
    with pytest.raises(ValueError, match="different transition scope"):
        assess(scope, requirements, (changed, *observations[1:]))


@pytest.mark.parametrize(
    "field", ["source_revision", "source_configuration_revision", "target_configuration_revision"]
)
def test_changed_code_or_environment_configuration_invalidates_old_evidence(field):
    scope, requirements, observations = setup()
    with pytest.raises(ValueError, match="different transition scope"):
        assess(replace(scope, **{field: "e" * 64}), requirements, observations)


def test_changed_criterion_and_conflicting_results_cannot_reuse_evidence():
    scope, requirements, observations = setup()
    changed = replace(requirements[0], criterion_revision="e" * 64)
    with pytest.raises(ValueError, match="different preservation criterion"):
        assess(scope, (changed, *requirements[1:]), observations)
    with pytest.raises(ValueError, match="Ambiguous duplicate"):
        assess(scope, requirements, (*observations, replace(observations[0], status="failed")))


def test_baseline_cannot_be_removed_and_extra_app_constraints_are_carried_forward():
    scope, requirements, observations = setup()
    with pytest.raises(ValueError, match="cannot be omitted"):
        assess(scope, requirements[1:], ())
    extra = PreservationRequirement("gpu_runtime", "registered-gpu-criterion", "e" * 64)
    report = assess(scope, (*requirements, extra), observations)
    assert report["unresolved_capabilities"] == ["gpu_runtime"]
    with pytest.raises(ValueError, match="Duplicate preservation"):
        assess(scope, (*requirements, requirements[0]), ())


def test_report_identity_is_canonical_and_binds_criteria_results_and_freshness_policy():
    scope, requirements, observations = setup()
    original = assess()
    reordered = assess(scope, tuple(reversed(requirements)), tuple(reversed(observations)))
    assert original == reordered
    changed_result = assess(
        scope, requirements, (replace(observations[0], status="failed"), *observations[1:])
    )
    changed_expiry = assess(
        scope,
        requirements,
        (replace(observations[0], expires_at=NOW + timedelta(seconds=59)), *observations[1:]),
    )
    assert (
        len(
            {
                original["report_id"],
                changed_result["report_id"],
                changed_expiry["report_id"],
                assess(max_age_seconds=30)["report_id"],
            }
        )
        == 4
    )
    assert assess(now=NOW + timedelta(seconds=60))["status"] == "blocked"


@pytest.mark.parametrize("age", [0, 301, True, 1.5])
def test_observation_window_cannot_be_unbounded_or_boolean(age):
    with pytest.raises(ValueError, match="Bounded observation age"):
        assess(max_age_seconds=age)


def test_contract_rejects_unbounded_mutable_and_unpinned_inputs():
    scope, requirements, observations = setup()
    with pytest.raises(ValueError, match="immutable preservation requirements"):
        assess(scope, list(requirements), observations)
    with pytest.raises(ValueError, match="immutable preservation observations"):
        assess(scope, requirements, observations * 6)
    with pytest.raises(ValueError, match="Distinct registered environments"):
        replace(scope, target_environment_ref=scope.source_environment_ref)
    with pytest.raises(ValueError, match="Registered transition reference"):
        replace(observations[0], evidence_ref="postgresql://private:secret@host/db")
    with pytest.raises(ValueError, match="revision digest"):
        replace(requirements[0], criterion_revision="latest")
    with pytest.raises(ValueError, match="Timezone-aware"):
        replace(observations[0], observed_at=NOW.replace(tzinfo=None))
    with pytest.raises(ValueError, match="Positive evidence lifetime"):
        replace(observations[0], expires_at=observations[0].observed_at)
