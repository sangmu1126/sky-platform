"""A signed hold is persisted with CAS in actual disposable PostgreSQL."""

import base64
from copy import deepcopy
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from adapters.state.postgres import PostgresDeploymentRecordStore
from application.security_signals import RegisteredDetector, SecuritySignalIntake, canonical_signal
from domain.access import Role
from tests.contract.test_operation_store import database as database  # noqa: PLC0414
from tests.unit.test_deployment_writes import ID, Records, principal


def test_signed_signal_cannot_reuse_an_old_revision_and_same_event_does_not_clear_hold(database):
    records = PostgresDeploymentRecordStore(database, workspace=uuid4().hex)
    initial = deepcopy(Records().job)
    initial.update(source_digest="a" * 64, promotion_automation_consent={"previous": True})
    records.save_job(ID, initial)
    key = Ed25519PrivateKey.generate()
    detector = RegisteredDetector(
        "test-detector",
        "org1",
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        frozenset({"untrusted_artifact"}),
        "game",
    )
    intake = SecuritySignalIntake(records, (detector,))
    payload = {
        "version": 1,
        "detector_id": detector.detector_id,
        "event_id": uuid4().hex,
        "organization_id": "org1",
        "application_id": "game",
        "job_id": ID,
        "source_digest": "a" * 64,
        "record_revision": 1,
        "reason": "untrusted_artifact",
        "observed_at": "2026-10-29T00:00:00+00:00",
        "expires_at": "2026-10-29T00:04:00+00:00",
    }

    def envelope():
        return {
            "payload": deepcopy(payload),
            "signature": base64.b64encode(key.sign(canonical_signal(payload))).decode(),
        }

    # Another legitimate change makes the observed event stale.
    records.save_job(ID, {**initial, "status": "succeeded"}, expected_revision=1)
    actor = principal(role=Role.ADMIN)
    with pytest.raises(ValueError, match="current deployment"):
        intake.apply(actor, envelope(), now="2026-10-29T00:01:00+00:00")
    assert records.load_job(ID).record.get("security_hold") is None
    payload["record_revision"] = 2
    hold = intake.apply(actor, envelope(), now="2026-10-29T00:01:00+00:00")
    assert records.load_job(ID).revision == 3
    assert records.load_job(ID).record["promotion_automation_consent"] is None
    assert intake.apply(actor, envelope(), now="2026-10-29T00:01:00+00:00") == hold
    assert records.load_job(ID).revision == 3
