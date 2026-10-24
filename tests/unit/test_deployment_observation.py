from copy import deepcopy
from unittest.mock import Mock

import pytest

from application.deployment_observation import DeploymentObservationRecorder
from application.security_hold import SecurityHold
from domain.access import Role
from ports.state import RecordConflict
from tests.unit.test_deployment_writes import principal
from tests.unit.test_operating_review import ID, NOW

pytest_plugins = ["tests.unit.test_operating_review"]


def observer(records, probe=None, revalidate=None):
    actor = principal(role=Role.ADMIN)
    return DeploymentObservationRecorder(
        records,
        probe or Mock(return_value={"healthy": True, "checked_at": NOW, "reason": "HTTP checked"}),
        clock=lambda: NOW,
        revalidate=revalidate or (lambda: actor),
    )


def test_collect_while_held_records_current_boundary_without_releasing_or_approving(operating_review_setup):
    records, _, _ = operating_review_setup
    actor = principal(role=Role.ADMIN)
    SecurityHold(records).place(actor, ID, incident_id="INC-1", reason="untrusted_artifact", now=NOW)
    job = deepcopy(records.job)
    result = observer(records).collect(actor, ID)
    assert result == {"healthy": True, "checked_at": NOW, "health_revision": 2}
    assert records.job == job
    assert (
        records.health[-1]["deployment_binding"]["security_review_boundary"]
        == job["security_review_boundary"]
    )
    assert records.health[-1]["source"] == "manual"


@pytest.mark.parametrize("role", [Role.VIEWER, Role.DEPLOYER])
def test_non_admin_and_foreign_admin_cannot_probe(operating_review_setup, role):
    records, _, _ = operating_review_setup
    probe = Mock()
    service = observer(records, probe)
    with pytest.raises(PermissionError):
        service.collect(principal(role=role), ID)
    actor = principal(org="foreign", role=Role.ADMIN)
    with pytest.raises(FileNotFoundError):
        observer(records, probe, lambda: actor).collect(actor, ID)
    probe.assert_not_called()


@pytest.mark.parametrize(
    "result",
    [
        {"healthy": "false", "checked_at": NOW, "reason": "unchecked"},
        {"healthy": True, "checked_at": "2026-10-10T00:00:00Z", "reason": "cached"},
        {"healthy": True, "checked_at": "2026-10-12T00:00:00Z", "reason": "future"},
        {"healthy": True, "checked_at": NOW, "reason": ""},
        None,
    ],
)
def test_unverified_probe_output_never_gets_a_fresh_timestamp(operating_review_setup, result):
    records, _, _ = operating_review_setup
    before = deepcopy(records.health)
    with pytest.raises(ValueError):
        observer(records, Mock(return_value=result)).collect(principal(role=Role.ADMIN), ID)
    assert records.health == before


def test_probe_errors_are_redacted_and_failures_are_not_success(operating_review_setup):
    records, _, _ = operating_review_setup
    with pytest.raises(OSError) as error:
        observer(records, Mock(side_effect=RuntimeError("secret-password"))).collect(
            principal(role=Role.ADMIN), ID
        )
    assert "secret" not in str(error.value)
    result = observer(
        records, Mock(return_value={"healthy": False, "checked_at": NOW, "reason": "HTTP failed"})
    ).collect(principal(role=Role.ADMIN), ID)
    assert result["healthy"] is False and records.health[-1]["healthy"] is False


def test_incident_or_membership_change_during_probe_prevents_write(operating_review_setup):
    records, _, _ = operating_review_setup
    actor = principal(role=Role.ADMIN)

    def probe(job):
        SecurityHold(records).place(actor, ID, incident_id="INC-1", reason="untrusted_artifact", now=NOW)
        return {"healthy": True, "checked_at": NOW, "reason": "HTTP checked"}

    before = deepcopy(records.health)
    with pytest.raises(RecordConflict):
        observer(records, probe).collect(actor, ID)
    assert records.health == before
    revalidate = Mock(side_effect=[actor, principal(role=Role.VIEWER)])
    with pytest.raises(PermissionError):
        observer(records, revalidate=revalidate).collect(actor, ID)
    assert records.health == before


def test_concurrent_health_write_is_not_overwritten(operating_review_setup):
    records, _, _ = operating_review_setup

    def probe(job):
        records.health_revision += 1
        return {"healthy": True, "checked_at": NOW, "reason": "HTTP checked"}

    before = deepcopy(records.health)
    with pytest.raises(RecordConflict):
        observer(records, probe).collect(principal(role=Role.ADMIN), ID)
    assert records.health == before


def test_hold_racing_after_snapshot_check_cannot_turn_old_probe_into_current_evidence(operating_review_setup):
    records, policy, review = operating_review_setup
    actor = principal(role=Role.ADMIN)

    def incident_at_health_commit(store):
        store.before_save = None
        SecurityHold(store).place(actor, ID, incident_id="INC-race", reason="untrusted_artifact", now=NOW)

    records.before_save = incident_at_health_commit
    observer(records).collect(actor, ID)
    # Cross-record writes are not one transaction: a stale observation can persist.
    # It must remain unusable after a hypothetical future release.
    records.job["security_hold"] = None
    with pytest.raises(ValueError, match="not bound"):
        review.review(actor, ID, policy, now=NOW)
