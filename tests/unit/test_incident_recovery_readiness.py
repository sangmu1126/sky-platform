from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from application.incident_artifact_review import metadata_digest
from application.incident_recovery_readiness import OPERATIONS, UNSUPPORTED, IncidentRecoveryReadiness
from ports.state import RecordConflict
from tests.unit.test_incident_artifact_review import approve
from tests.unit.test_incident_artifact_review import context as context  # noqa: PLC0414
from tests.unit.test_operating_review import ID


@pytest.fixture
def ready(context):
    c = context
    for index, (_, (field, phase)) in enumerate(OPERATIONS.items()):
        if field not in c.records.job:
            c.records.job[field] = {
                "operation_id": str(index + 1) * 32,
                "phase": phase,
                "incident_id": c.options["incident_id"],
                "boundary_id": c.options["expected_boundary"],
            }
    approve(c)
    receipts = {
        "runtime": {"registered_service_quiescent": True},
        "runtime_containment": {"scale_down_configuration_observed": True},
        "database_restriction": {
            "observed_state": "restricted",
            "login_enabled": False,
            "active_sessions": 0,
        },
        "candidate_credentials": {
            "observed_state": "restricted_candidate_observed",
            "candidate_state": "registered_candidate",
            "login_enabled": False,
            "active_sessions": 0,
        },
        "credential_executor": {"executor_state": "stopped"},
        "secret_access": {"policy_state": "runtime_roles_denied", "candidate_protected": True},
    }

    def inspector(name):
        def inspect(*_, **options):
            record = c.records.job[OPERATIONS[name][0]] if name in OPERATIONS else None
            return {
                **receipts[name],
                "metadata_revision": options["expected_revision"],
                "observed_at": c.moment[0].isoformat(),
                "read_only": True,
                "state_changed": False,
                "recovery_authorized": False,
                **(
                    {"operation_id": record["operation_id"], "persisted_phase": record["phase"]}
                    if record
                    else {}
                ),
            }

        return Mock(inspect=Mock(side_effect=inspect))

    inspections = {name: inspector(name) for name in receipts}
    gate = IncidentRecoveryReadiness(
        c.records, c.service, inspections, clock=lambda: c.moment[0].isoformat(), revalidate=lambda: c.actor
    )
    c.options["expected_revision"] = c.records.revision
    return SimpleNamespace(c=c, gate=gate, inspections=inspections, receipts=receipts)


def check(r):
    return r.gate.check(r.c.actor, ID, review_id="c" * 32, **r.c.options)


def test_positive_limited_observations_do_not_clear_unknown_execution_controls(ready):
    r = ready
    before, saves = deepcopy(r.c.records.job), r.c.records.save_calls
    result = check(r)
    assert all(result["checks"][name]["status"] == "verified" for name in ("artifact_review", *r.inspections))
    assert all(name in result["blocking_checks"] for name in UNSUPPORTED)
    assert not result["ready_for_recovery"] and not result["execution_authorized"]
    assert not result["recovery_authorized"] and not result["hold_released"]
    assert result["read_only"] and not result["state_changed"]
    assert r.c.records.job == before and r.c.records.save_calls == saves


def test_missing_live_configuration_is_not_proof_that_database_checks_are_unnecessary(ready):
    ready.gate.inspections = {}
    result = check(ready)
    assert result["checks"]["database_restriction"]["reason_code"] == "live_inspector_not_configured"
    assert result["checks"]["runtime"]["status"] == "blocked"


@pytest.mark.parametrize("change", ["active", "stale", "foreign", "unsafe", "unavailable"])
def test_invalid_or_failed_native_receipts_cannot_pass(ready, change):
    r = ready
    if change == "active":
        r.receipts["runtime"]["registered_service_quiescent"] = False
    else:
        old = r.inspections["runtime"].inspect.side_effect

        def changed(*a, **kw):
            if change == "unavailable":
                raise OSError("private-password-diagnostic")
            value = old(*a, **kw)
            if change == "stale":
                value["observed_at"] = (r.c.moment[0] - timedelta(seconds=1)).isoformat()
            elif change == "foreign":
                value["metadata_revision"] += 1
            else:
                value["state_changed"] = True
            return value

        r.inspections["runtime"].inspect.side_effect = changed
    result = check(r)
    assert result["checks"]["runtime"]["status"] == "blocked"
    assert "private-password-diagnostic" not in str(result)


def test_unsettled_operation_stays_blocked_even_if_no_login_observed(ready):
    r = ready
    # Fixture-only alteration before a fresh approval pins the unsettled phase.
    r.c.records.job["security_database_restriction"]["phase"] = "applying"
    r.c.records.job["security_artifact_review"]["metadata_digest"] = metadata_digest(r.c.records.job)
    result = check(r)
    assert result["checks"]["database_restriction"]["reason_code"] == "operation_outcome_unsettled"


def test_operation_scope_change_is_not_reused_from_another_incident(ready):
    r = ready
    r.c.records.job["security_database_restriction"]["incident_id"] = "FOREIGN"
    r.c.records.job["security_artifact_review"]["metadata_digest"] = metadata_digest(r.c.records.job)
    result = check(r)
    assert result["checks"]["database_restriction"]["reason_code"] == "operation_scope_invalid"
    r.inspections["database_restriction"].inspect.assert_not_called()


def test_concurrent_revision_change_aborts_entire_report(ready):
    r = ready

    def changed(*_, **kw):
        r.c.records.revision += 1
        raise OSError("provider failure")

    r.inspections["runtime"].inspect.side_effect = changed
    with pytest.raises(RecordConflict):
        check(r)


def test_review_expiring_during_probes_cannot_yield_fresh_readiness(ready):
    r = ready
    old = r.inspections["runtime"].inspect.side_effect

    def delayed(*a, **kw):
        r.c.moment[0] += timedelta(seconds=301)
        return old(*a, **kw)

    r.inspections["runtime"].inspect.side_effect = delayed
    with pytest.raises(ValueError):
        check(r)


def test_unknown_probe_cannot_claim_execution_fencing(ready):
    r = ready
    with pytest.raises(ValueError):
        IncidentRecoveryReadiness(
            r.c.records,
            r.c.service,
            {"execution_exclusion": Mock()},
            clock=lambda: r.c.moment[0].isoformat(),
            revalidate=lambda: r.c.actor,
        )
