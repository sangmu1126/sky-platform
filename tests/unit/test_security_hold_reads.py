import json
from unittest.mock import Mock

import pytest

from application.deployment_reads import DeploymentReadService
from domain.access import Role
from ports.deployment_reads import DeploymentSnapshot, SnapshotPage
from tests.unit.test_deployment_writes import Records, principal
from tests.unit.test_operating_review import ID, NOW


def setup(hold):
    job = {**Records().job, "security_hold": hold}
    snapshot = DeploymentSnapshot(job, [], 1)
    reads = Mock(detail=Mock(return_value=snapshot), page=Mock(return_value=SnapshotPage((snapshot,), None)))
    return job, DeploymentReadService(reads)


def hold():
    return {
        "incident_id": "INC-private-1",
        "reason": "credential_exposure",
        "recorded_at": NOW,
        "recorded_by": "security-admin",
    }


@pytest.mark.parametrize("role", [Role.VIEWER, Role.DEPLOYER])
def test_non_admin_detail_exposes_only_hold_state(role):
    job, service = setup(hold())
    detail = service.detail(principal(role=role), ID)
    assert "security_hold" not in detail
    assert detail["security_status"] == {"status": "held", "promotion_blocked": True, "hold": None}
    assert "INC-private-1" not in json.dumps(detail)
    assert "credential_exposure" not in json.dumps(detail)
    assert job["security_hold"] == hold()


@pytest.mark.parametrize("role", list(Role))
def test_lists_and_releases_never_include_incident_details(role):
    _, service = setup(hold())
    for items in (
        service.summaries(principal(role=role)).items,
        service.releases(principal(role=role), "game").items,
    ):
        assert items[0]["security_status"]["status"] == "held"
        assert "INC-private-1" not in json.dumps(items)
        assert "credential_exposure" not in json.dumps(items)


def test_admin_detail_is_sanitized_detached_and_still_owned():
    job, service = setup(hold())
    detail = service.detail(principal(role=Role.ADMIN), ID)
    assert detail["security_status"]["hold"] == hold() and "security_hold" not in detail
    detail["security_status"]["hold"]["incident_id"] = "changed"
    assert job["security_hold"]["incident_id"] == "INC-private-1"
    with pytest.raises(FileNotFoundError):
        service.detail(principal(org="foreign", role=Role.ADMIN), ID)


@pytest.mark.parametrize("bad", [False, {}, {"password": "must-not-disclose"}])
def test_corrupt_hold_remains_blocked_without_echoing_raw_record(bad):
    _, service = setup(bad)
    for role in Role:
        detail = service.detail(principal(role=role), ID)
        assert detail["security_status"]["promotion_blocked"] is True
        assert detail["security_status"]["hold"] is None
        assert "must-not-disclose" not in json.dumps(detail)


@pytest.mark.parametrize("role", list(Role))
def test_credential_preparation_details_are_operator_cli_only(role):
    job, service = setup(None)
    job["security_credential_preparation"] = {"candidate_secret_ref": "must-not-expose-candidate"}
    detail = service.detail(principal(role=role), ID)
    assert "security_credential_preparation" not in detail
    assert "must-not-expose-candidate" not in json.dumps(detail)
    assert detail["security_status"]["promotion_blocked"] is True
    for items in (
        service.summaries(principal(role=role)).items,
        service.releases(principal(role=role), "game").items,
    ):
        assert "must-not-expose-candidate" not in json.dumps(items)
        assert items[0]["security_status"]["promotion_blocked"] is True


@pytest.mark.parametrize("role", list(Role))
def test_new_source_review_is_operator_only_and_never_unblocks_promotion(role):
    job, service = setup(None)
    job["security_recovery_source_review"] = {"candidate": "must-not-expose-source"}
    detail = service.detail(principal(role=role), ID)
    assert "security_recovery_source_review" not in detail
    assert "must-not-expose-source" not in json.dumps(detail)
    assert detail["security_status"]["promotion_blocked"] is True
    for items in (
        service.summaries(principal(role=role)).items,
        service.releases(principal(role=role), "game").items,
    ):
        assert "must-not-expose-source" not in json.dumps(items)
        assert items[0]["security_status"]["promotion_blocked"] is True
