"""Authenticated typed findings can propose holds only for the registered app."""

from copy import deepcopy
from unittest.mock import Mock
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from application.security_observations import SecurityObservationRouter
from application.security_signals import RegisteredDetector, SecuritySignalIntake
from domain.access import Role
from tests.unit.test_deployment_writes import Records, principal
from tests.unit.test_operating_review import ID

NOW = "2026-10-30T00:00:00+00:00"


def setup_router():
    records = Records()
    records.job["source_digest"] = "a" * 64
    records.job["promotion_automation_consent"] = {"existing": True}
    actor = principal(role=Role.ADMIN)
    key = Ed25519PrivateKey.generate()
    detector = RegisteredDetector(
        "registered-collector",
        actor.organization_id,
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        frozenset({"credential_exposure", "suspected_compromise", "untrusted_artifact"}),
        "game",
    )
    audit = Mock(return_value={"append_confirmed": True})
    router = SecurityObservationRouter(
        detector,
        key,
        audit,
        scope={"job_id": ID, "source_digest": "a" * 64, "record_revision": records.revision},
    )
    return router, records, actor, SecuritySignalIntake(records, (detector,)), audit


def test_authenticated_fact_audit_then_operator_hold_never_clears_healthy_app():
    router, records, actor, intake, audit = setup_router()
    original = deepcopy(records.job)
    result = router.route(
        "forbidden_secret_read", event_id=str(uuid4()), observed_at=NOW, now=NOW, evidence_digest="b" * 64
    )
    audit.assert_called_once()
    assert records.job == original  # Collection alone cannot mutate deployments.
    hold = intake.apply(actor, result["signed_hold_proposal"], now=NOW)
    assert hold["reason"] == "credential_exposure" and records.job["promotion_automation_consent"] is None
    records.job["health"] = {"healthy": True}  # A healthy response is no security release.
    assert records.job["security_hold"] == hold
    assert result["automatic_release_permitted"] is False


@pytest.mark.parametrize(
    "kind", ["repeated_auth_denials", "resource_budget_exhausted", "database_capacity_exhausted"]
)
def test_expected_capacity_denial_needs_review_without_automatic_hold(kind):
    router, records, _, _, audit = setup_router()
    result = router.route(kind, event_id=str(uuid4()), observed_at=NOW, now=NOW, evidence_digest="b" * 64)
    assert result["signed_hold_proposal"] is None and result["operator_review_required"]
    assert records.save_calls == 0
    audit.assert_called_once()


def test_failed_audit_cannot_create_a_hold_proposal():
    router, records, _, _, audit = setup_router()
    audit.side_effect = OSError("audit unavailable")
    with pytest.raises(OSError):
        router.route(
            "artifact_identity_mismatch",
            event_id=str(uuid4()),
            observed_at=NOW,
            now=NOW,
            evidence_digest="b" * 64,
        )
    assert records.save_calls == 0


@pytest.mark.parametrize("change", ["app", "source", "revision", "expired"])
def test_cross_app_stale_or_altered_signals_have_zero_state_effect(change):
    router, records, actor, intake, _ = setup_router()
    result = router.route(
        "forbidden_secret_read", event_id=str(uuid4()), observed_at=NOW, now=NOW, evidence_digest="b" * 64
    )
    envelope = result["signed_hold_proposal"]
    if change == "app":
        envelope["payload"]["application_id"] = "another-app"
    elif change == "source":
        records.job["source_digest"] = "c" * 64
    elif change == "revision":
        records.revision += 1
    current = NOW if change != "expired" else "2026-10-30T00:06:00+00:00"
    with pytest.raises(ValueError):
        intake.apply(actor, envelope, now=current)
    assert records.save_calls == 0


def test_native_collection_cannot_accept_an_uploaded_report():
    router, records, *_ = setup_router()
    with pytest.raises(ValueError):
        router.collect_inventory(Mock(), "iam", {"events": []}, now=NOW)
    assert records.save_calls == 0


def test_blocked_network_is_warning_without_hold_authority():
    router, records, _, _, audit = setup_router()
    value = router.route(
        "blocked_network_egress", event_id=str(uuid4()), observed_at=NOW, now=NOW, evidence_digest="f" * 64
    )
    assert value["signed_hold_proposal"] is None
    assert value["event"]["severity"] == "warning" and records.save_calls == 0
    audit.assert_called_once()
