"""Authentic bounded signals only; no automatic security clearance or cloud effects."""

import base64
from copy import deepcopy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from application.security_signals import RegisteredDetector, SecuritySignalIntake, canonical_signal
from domain.access import Role
from tests.unit.test_deployment_writes import Records, principal
from tests.unit.test_operating_review import ID

NOW = "2026-10-29T00:00:00+00:00"


@pytest.fixture
def signal():
    records = Records()
    records.job["source_digest"] = "a" * 64
    records.job["promotion_automation_consent"] = {"old": True}
    actor = principal(role=Role.ADMIN)
    key = Ed25519PrivateKey.generate()
    detector = RegisteredDetector(
        "egress1",
        actor.organization_id,
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        frozenset({"credential_exposure"}),
        "game",
    )
    payload = {
        "version": 1,
        "detector_id": "egress1",
        "event_id": "b" * 32,
        "organization_id": actor.organization_id,
        "application_id": "game",
        "job_id": ID,
        "source_digest": "a" * 64,
        "record_revision": records.revision,
        "reason": "credential_exposure",
        "observed_at": NOW,
        "expires_at": "2026-10-29T00:04:00+00:00",
    }

    def sign(value):
        return {"payload": value, "signature": base64.b64encode(key.sign(canonical_signal(value))).decode()}

    return records, actor, SecuritySignalIntake(records, (detector,)), payload, sign


def test_verified_signal_places_hold_and_revokes_old_consent_once(signal):
    records, actor, intake, payload, sign = signal
    envelope = sign(payload)
    hold = intake.apply(actor, envelope, now=NOW)
    assert hold["incident_id"] == "signal:" + payload["event_id"]
    assert records.job["promotion_automation_consent"] is None
    assert intake.apply(actor, envelope, now=NOW) == hold
    assert records.save_calls == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("organization_id", "foreign"),
        ("source_digest", "c" * 64),
        ("record_revision", 999),
        ("reason", "suspected_compromise"),
        ("expires_at", "2026-10-29T01:00:00+00:00"),
        ("observed_at", "2026-10-29T00:01:00+00:00"),
        ("version", True),
        ("job_id", "not-a-job"),
        ("record_revision", True),
    ],
)
def test_even_signed_out_of_scope_signal_has_no_effect(signal, field, value):
    records, actor, intake, payload, sign = signal
    payload[field] = value
    with pytest.raises(ValueError):
        intake.apply(actor, sign(payload), now=NOW)
    assert records.save_calls == 0


def test_tampering_or_invalid_signature_is_not_a_hold_signal(signal):
    records, actor, intake, payload, sign = signal
    envelope = sign(payload)
    envelope["payload"] = deepcopy(payload)
    envelope["payload"]["event_id"] = "f" * 32
    with pytest.raises(ValueError):
        intake.apply(actor, envelope, now=NOW)
    envelope["signature"] = "!" * 100
    with pytest.raises(ValueError):
        intake.apply(actor, envelope, now=NOW)
    assert records.save_calls == 0


def test_low_privilege_user_cannot_submit_even_a_valid_signal(signal):
    records, _, intake, payload, sign = signal
    with pytest.raises(PermissionError):
        intake.apply(principal(role=Role.DEPLOYER), sign(payload), now=NOW)
    assert records.save_calls == 0
