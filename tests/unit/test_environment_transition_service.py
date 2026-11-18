"""Only authorized server registrations can dispatch preservation collectors."""

from dataclasses import replace
from unittest.mock import Mock

import pytest

from application.environment_transition import (
    EnvironmentTransitionReviewService,
    OperatorTransitionRegistry,
    RegisteredEnvironmentTransition,
    RegisteredPreservationCollector,
)
from domain.access import LoginSource, Principal, Role
from ports.environment_transition import PreservationCollectionUnavailable
from tests.unit.test_environment_transition import NOW, setup


def service():
    scope, requirements, observations = setup()
    collector = Mock(
        collect=Mock(
            return_value=tuple(replace(item, verifier_ref="registered-reader") for item in observations)
        )
    )
    binding = RegisteredPreservationCollector("registered-reader", requirements, collector)
    registration = RegisteredEnvironmentTransition("migration-1", scope, requirements, (binding,))
    registry = OperatorTransitionRegistry((registration,))
    authorizer = Mock()
    membership = Mock(side_effect=lambda principal: principal)
    review = EnvironmentTransitionReviewService(
        registry, authorizer, current_principal=membership, clock=lambda: NOW
    )
    actor = Principal("alice", "org", Role.DEPLOYER, LoginSource.CORPORATE_SSO)
    return review, actor, collector, authorizer, membership, registration


def test_id_only_review_collects_registered_evidence_without_execution_authority():
    review, actor, collector, auth, membership, registration = service()
    result = review.review(actor, "migration-1")
    collector.collect.assert_called_once_with(registration.scope, registration.requirements)
    assert auth.authorize.call_count == 3 and membership.call_count == 4
    assert result["status"] == "verified" and result["execution_authorized"] is False


def test_internal_id_based_collection_can_persist_only_its_computed_report():
    review, actor, _, _, _, _ = service()
    store = Mock()
    review.review_store = store
    stored, document = review.review_and_record(actor, "migration-1")
    store.record.assert_called_once_with(actor, "migration-1", document)
    assert stored is store.record.return_value and document["execution_authorized"] is False


def test_revocation_during_persistence_does_not_publish_a_stale_review():
    review, actor, _, _, membership, _ = service()

    def recorded(*_args):
        membership.side_effect = lambda _: None
        return object()

    review.review_store = Mock(record=Mock(side_effect=recorded))
    with pytest.raises(PermissionError, match="after recording"):
        review.review_and_record(actor, "migration-1")


def test_unconfigured_durable_store_and_unauthenticated_actor_do_not_collect():
    review, _, collector, _, _, _ = service()
    with pytest.raises(PermissionError):
        review.review_and_record(None, "migration-1")
    collector.collect.assert_not_called()
    with pytest.raises(ValueError, match="not configured"):
        review.review_and_record(service()[1], "migration-1")
    collector.collect.assert_not_called()


@pytest.mark.parametrize("change", [{"organization_id": "other"}, {"role": Role.VIEWER}])
def test_foreign_or_read_only_actor_cannot_trigger_resource_reads(change):
    review, actor, collector, *_ = service()
    with pytest.raises((FileNotFoundError, PermissionError)):
        review.review(replace(actor, **change), "migration-1")
    collector.collect.assert_not_called()


def test_unknown_app_ownership_denies_collection_instead_of_adopting_it():
    review, actor, collector, auth, *_ = service()
    auth.authorize.side_effect = FileNotFoundError("Application not found")
    with pytest.raises(FileNotFoundError):
        review.review(actor, "migration-1")
    collector.collect.assert_not_called()


@pytest.mark.parametrize("when", [0, 1, 2, 3])
def test_membership_revocation_is_rechecked_before_and_after_collection(when):
    review, actor, collector, _auth, membership, _ = service()
    membership.side_effect = [actor] * when + [None]
    with pytest.raises(PermissionError, match="membership changed"):
        review.review(actor, "migration-1")
    assert collector.collect.call_count == (1 if when == 3 else 0)


def test_changed_registration_during_collection_cannot_publish_old_result():
    review, actor, collector, _, _, registration = service()
    next_registration = replace(
        registration, scope=replace(registration.scope, target_configuration_revision="e" * 64)
    )
    review.registry = Mock(resolve=Mock(side_effect=[registration] * 3 + [next_registration]))
    with pytest.raises(ValueError, match="changed during collection"):
        review.review(actor, "migration-1")
    collector.collect.assert_called_once()


def test_collection_error_is_unverified_and_does_not_disclose_diagnostics():
    review, actor, collector, *_ = service()
    collector.collect.side_effect = PreservationCollectionUnavailable("private-secret")
    result = review.review(actor, "migration-1")
    assert result["status"] == "blocked" and "private-secret" not in str(result)
    assert all(item["status"] == "unverified" for item in result["checks"])


@pytest.mark.parametrize("change", [{"verifier_ref": "another"}, {"origin": "agent_proposal"}])
def test_registered_collector_cannot_impersonate_other_verifier_or_report_model_proof(change):
    review, actor, collector, *_ = service()
    results = collector.collect.return_value
    collector.collect.return_value = (replace(results[0], **change), *results[1:])
    with pytest.raises(ValueError, match="evidence authority"):
        review.review(actor, "migration-1")


def test_collector_cannot_verify_unassigned_criterion():
    review, actor, _collector, _, _, registration = service()
    subset = replace(registration.collectors[0], requirements=(registration.requirements[0],))
    review.registry = OperatorTransitionRegistry((replace(registration, collectors=(subset,)),))
    with pytest.raises(ValueError, match="Invalid registered collection result"):
        review.review(actor, "migration-1")


def test_duplicate_collector_and_requirement_registration_is_rejected():
    *_, registration = service()
    with pytest.raises(ValueError, match="Duplicate registered verifier"):
        replace(registration, collectors=registration.collectors * 2)
    with pytest.raises(ValueError, match="ambiguously assigned"):
        replace(
            registration,
            collectors=(*registration.collectors, replace(registration.collectors[0], verifier_ref="other")),
        )
    with pytest.raises(ValueError, match="Duplicate registered transition"):
        OperatorTransitionRegistry((registration, registration))


def test_unknown_or_untrusted_request_values_are_rejected_before_collection():
    review, actor, collector, *_ = service()
    with pytest.raises(FileNotFoundError):
        review.review(actor, "unknown")
    with pytest.raises(ValueError, match="Registered transition reference"):
        review.review(actor, "https://untrusted.example/db")
    with pytest.raises(PermissionError, match="Authenticated"):
        review.review({"role": "admin"}, "migration-1")
    collector.collect.assert_not_called()
