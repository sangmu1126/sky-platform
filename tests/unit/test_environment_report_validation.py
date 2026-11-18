from copy import deepcopy
from dataclasses import replace

import pytest

from engine.environment_transition import validate_environment_transition_report
from tests.unit.test_environment_transition import assess, setup


@pytest.mark.parametrize("missing", [True, False])
def test_persisted_reports_recompute_both_verified_and_blocked_results_without_authorizing(missing):
    report = assess(observations=() if missing else None)
    validated = validate_environment_transition_report(report)
    assert validated == report and validated is not report
    assert validated["execution_authorized"] is False and validated["ready_to_cutover"] is False
    validated["checks"].clear()
    assert report["checks"]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(status="verified", unresolved_capabilities=[]),
        lambda r: r.update(execution_authorized=True),
        lambda r: r.update(ready_to_cutover=True),
        lambda r: r.update(approval_scope="execute"),
        lambda r: r.update(report_id="ENV-" + "a" * 64),
        lambda r: r.update(schema_version=True),
        lambda r: r.update(checks=[]),
        lambda r: r["scope"].update(source_revision="b" * 64),
        lambda r: r.update(requirements=r["requirements"][:-1]),
        lambda r: r.update(extra="not-in-schema"),
    ],
)
def test_status_and_scope_edits_cannot_remove_obligations_from_blocked_reports(mutate):
    report = assess(observations=())
    mutate(report)
    with pytest.raises(ValueError, match="persisted"):
        validate_environment_transition_report(report)


def test_agent_claims_remain_unverified_after_storage_round_trip():
    scope, requirements, observations = setup()
    proposed = tuple(replace(v, origin="agent_proposal") for v in observations)
    report = assess(scope, requirements, proposed)
    validated = validate_environment_transition_report(report)
    assert validated["status"] == "blocked" and len(validated["unresolved_capabilities"]) == 12
    tampered = deepcopy(report)
    tampered["observations"][0]["origin"] = "collector"
    with pytest.raises(ValueError):
        validate_environment_transition_report(tampered)


@pytest.mark.parametrize("value", [None, [], {}, {"scope": {}}, {"oversize": "x" * (256 * 1024)}])
def test_malformed_or_unbounded_report_is_not_storable(value):
    with pytest.raises(ValueError):
        validate_environment_transition_report(value)
