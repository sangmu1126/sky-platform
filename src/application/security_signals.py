"""Signed detector observations may place holds, never clear or execute recovery.

Operator registers exact detector keys and allowed organization/reasons. Arbitrary
app logs, AI output, browser requests and self-declared JWKS URLs are not signals.
This boundary does not itself detect compromise or authenticate a cloud collector.
"""

import base64
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from application.deployment_writes import DeploymentMetadataWriter
from application.security_hold import REASONS, SecurityHold
from domain.access import Principal, Role

_FIELDS = frozenset({"version", "detector_id", "event_id", "organization_id", "application_id", "job_id",
                     "source_digest", "record_revision", "reason", "observed_at", "expires_at"})


@dataclass(frozen=True)
class RegisteredDetector:
    detector_id: str
    organization_id: str
    public_key: bytes
    reasons: frozenset[str]
    application_id: str

    def __post_init__(self):
        if (not isinstance(self.detector_id, str)
                or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", self.detector_id)
                or not isinstance(self.organization_id, str)
                or not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", self.organization_id)
                or not isinstance(self.application_id, str)
                or not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", self.application_id)
                or not isinstance(self.public_key, bytes) or len(self.public_key) != 32
                or not isinstance(self.reasons, frozenset) or not self.reasons
                or not self.reasons <= REASONS):
            raise ValueError("Exact trusted detector registration required")


def canonical_signal(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


class SecuritySignalIntake:
    def __init__(self, records, detectors):
        if (not isinstance(detectors, tuple) or not detectors
                or any(not isinstance(item, RegisteredDetector) for item in detectors)
                or len({item.detector_id for item in detectors}) != len(detectors)):
            raise ValueError("Unique trusted detectors required")
        self.records = records
        self.detectors = {item.detector_id: item for item in detectors}

    def apply(self, principal, envelope, *, now):
        if not isinstance(principal, Principal) or principal.role is not Role.ADMIN:
            raise PermissionError("Current administrator required for security signal intake")
        if (not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}
                or not isinstance(envelope["payload"], dict)
                or set(envelope["payload"]) != _FIELDS):
            raise ValueError("Exact signed security signal required")
        payload = envelope["payload"]
        try:
            detector = self.detectors[payload["detector_id"]]
            encoded = canonical_signal(payload)
            if (len(encoded) > 2048 or not isinstance(envelope["signature"], str)
                    or len(envelope["signature"]) != 88):
                raise ValueError()
            signature = base64.b64decode(envelope["signature"], validate=True)
            if len(signature) != 64:
                raise ValueError()
            Ed25519PublicKey.from_public_bytes(detector.public_key).verify(signature, encoded)
            observed = datetime.fromisoformat(payload["observed_at"])
            expires = datetime.fromisoformat(payload["expires_at"])
            current = datetime.fromisoformat(now)
            if any(value.tzinfo is None or value.utcoffset() is None for value in (observed, expires, current)):
                raise ValueError()
            if not observed <= current < expires <= observed + timedelta(minutes=5):
                raise ValueError()
            if (type(payload["version"]) is not int or payload["version"] != 1
                    or payload["organization_id"] != detector.organization_id
                    or payload["organization_id"] != principal.organization_id
                    or payload["application_id"] != detector.application_id
                    or payload["reason"] not in detector.reasons
                    or not re.fullmatch(r"[0-9a-f]{32}", payload["event_id"])
                    or not re.fullmatch(r"[0-9a-f]{16}", payload["job_id"])
                    or not re.fullmatch(r"[0-9a-f]{64}", payload["source_digest"])
                    or type(payload["record_revision"]) is not int
                    or not 1 <= payload["record_revision"] < 2**63):
                raise ValueError()
        except (KeyError, TypeError, ValueError, InvalidSignature):
            raise ValueError("Security signal signature, scope or validity is invalid") from None
        snapshot = DeploymentMetadataWriter(self.records).snapshot(principal, payload["job_id"])
        if (snapshot.record.get("source_digest") != payload["source_digest"]
                or snapshot.record.get("application_id") != payload["application_id"]):
            raise ValueError("Security signal is for a different source revision")
        return SecurityHold(self.records).place(
            principal, payload["job_id"], incident_id="signal:" + payload["event_id"],
            reason=payload["reason"], now=now, expected_revision=payload["record_revision"],
        )
