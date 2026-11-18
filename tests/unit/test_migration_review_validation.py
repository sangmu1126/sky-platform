"""Only coherent internal preflight output can enter the metadata review ledger."""

from copy import deepcopy
from dataclasses import replace
from unittest.mock import Mock

import pytest

from application.database_migration_preflight import validate_preflight_report
from application.database_migration_reviews import DatabaseMigrationReviewService
from domain.access import LoginSource, Principal, Role
from domain.database_inventory import DatabaseInventoryUnavailable
from tests.unit.test_database_migration_preflight import case as case  # noqa: PLC0414 -- pytest fixture re-export
from tests.unit.test_database_migration_preflight import inspect as make_report


def test_internal_report_roundtrip_preserves_proof_and_blocked_execution(case):
    report = make_report(case)
    result = validate_preflight_report(report)
    assert result["preflight"]["evidence_id"] == report["preflight"]["evidence_id"]
    assert not result["ready_to_cutover"] and result["execution_status"] == "blocked"


def test_failed_collection_report_is_preserved_without_advancing_gates(case):
    case[3][0].inspect.side_effect = DatabaseInventoryUnavailable("private diagnostic")
    report = make_report(case)
    document = validate_preflight_report(report)
    assert document["preflight"]["status"] == "blocked"
    assert all(g["status"] == "unverified" for g in document["required_gates"])


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r.update(ready_to_cutover=True),
        lambda r: r.update(execution_status="approved"),
        lambda r: r.update(source_revision="b" * 64),
        lambda r: r["preflight"].update(evidence_id="DBI-" + "f" * 64),
        lambda r: r["preflight"].update(expires_at="2099-01-01T00:00:00+00:00"),
        lambda r: r["preflight"].update(password="SHOULD-NOT-PERSIST"),
        lambda r: r["required_gates"][-1].update(status="verified"),
        lambda r: r["source"].update(owner_ref="foreign"),
    ],
)
def test_changed_report_is_not_accepted_as_internal_evidence(case, change):
    report = deepcopy(make_report(case))
    change(report)
    with pytest.raises(ValueError, match="Invalid internal"):
        validate_preflight_report(report)


def test_unauthorized_principal_cannot_trigger_provider_reads(case):
    preflight, reviews = Mock(), Mock()
    reviews.authorize.side_effect = PermissionError("denied")
    with pytest.raises(PermissionError):
        DatabaseMigrationReviewService(preflight, reviews).review(
            Principal("alice", "org", Role.VIEWER, LoginSource.CORPORATE_SSO),
            *case[:3],
            source_revision="a" * 64,
        )
    preflight.inspect.assert_not_called()
    reviews.record.assert_not_called()


def test_service_collects_and_records_only_its_own_report(case):
    report = make_report(case)
    preflight, reviews = Mock(inspect=Mock(return_value=report)), Mock()
    actor = Principal("alice", "org", Role.DEPLOYER, LoginSource.CORPORATE_SSO)
    service = DatabaseMigrationReviewService(preflight, reviews)
    assert service.review(actor, *case[:3], source_revision="a" * 64) == reviews.record.return_value
    reviews.record.assert_called_once_with(actor, report)
    with pytest.raises(FileNotFoundError):
        service.review(replace(actor, organization_id="foreign"), *case[:3], source_revision="a" * 64)
    assert preflight.inspect.call_count == 1
