"""Registered collector facts to app-scoped signed holds; no model/log authority."""

import base64
import hashlib
import re
from datetime import datetime, timedelta
from uuid import UUID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from application.security_signals import RegisteredDetector, canonical_signal

# Source adapters supply typed facts. Unstructured log strings are never rules.
RULES = {
    "forbidden_secret_read": ("critical", "credential_exposure"),
    "unapproved_iam_change": ("critical", "suspected_compromise"),
    "artifact_identity_mismatch": ("critical", "untrusted_artifact"),
    "forbidden_network_egress": ("high", "suspected_compromise"),
    "blocked_network_egress": ("warning", None),
    "repeated_auth_denials": ("warning", None),
    "resource_budget_exhausted": ("warning", None),
    "database_capacity_exhausted": ("warning", None),
}


class SecurityObservationRouter:
    def __init__(self, detector, private_key, audit, *, scope):
        if (
            not isinstance(detector, RegisteredDetector)
            or not isinstance(private_key, Ed25519PrivateKey)
            or not callable(audit)
            or private_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            != detector.public_key
            or not isinstance(scope, dict)
            or set(scope) != {"job_id", "source_digest", "record_revision"}
            or not re.fullmatch(r"[0-9a-f]{16}", scope.get("job_id", ""))
            or not re.fullmatch(r"[0-9a-f]{64}", scope.get("source_digest", ""))
            or type(scope.get("record_revision")) is not int
            or scope["record_revision"] < 1
        ):
            raise ValueError("Exact app-bound registered collector signer and audit destination required")
        self.detector, self.key, self.audit, self.scope = detector, private_key, audit, dict(scope)

    def route(self, kind, *, event_id, observed_at, now, evidence_digest):
        if kind not in RULES or not isinstance(event_id, str) or str(UUID(event_id)) != event_id:
            raise ValueError("Registered typed security event and immutable provider identity required")
        occurrence, current = datetime.fromisoformat(observed_at), datetime.fromisoformat(now)
        if (
            any(t.tzinfo is None for t in (occurrence, current))
            or not occurrence <= current <= occurrence + timedelta(minutes=15)
            or not isinstance(evidence_digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", evidence_digest)
        ):
            raise ValueError("Recent authenticated observation evidence required")
        severity, reason = RULES[kind]
        if reason is not None and reason not in self.detector.reasons:
            raise ValueError("Collector has no authority for this hold reason")
        event = {
            "version": 1,
            "kind": kind,
            "severity": severity,
            "event_id": event_id,
            "organization_id": self.detector.organization_id,
            "application_id": self.detector.application_id,
            **self.scope,
            "detector_id": self.detector.detector_id,
            "observed_at": observed_at,
            "detected_at": now,
            "evidence_digest": evidence_digest,
            "security_clearance": False,
        }
        # Persist before proposing any action. This sink must have independent
        # append-only credentials; a failed audit cannot become a silent hold.
        receipt = self.audit(event)
        envelope = None
        if reason is not None:
            payload = {
                "version": 1,
                "detector_id": self.detector.detector_id,
                "event_id": hashlib.sha256(event_id.encode()).hexdigest()[:32],
                "organization_id": self.detector.organization_id,
                "application_id": self.detector.application_id,
                **self.scope,
                "reason": reason,
                "observed_at": now,
                "expires_at": (current + timedelta(minutes=5)).isoformat(),
            }
            envelope = {
                "payload": payload,
                "signature": base64.b64encode(self.key.sign(canonical_signal(payload))).decode(),
            }
        return {
            "event": event,
            "audit": receipt,
            "signed_hold_proposal": envelope,
            "operator_review_required": True,
            "automatic_release_permitted": False,
        }

    def collect_secrets(self, monitor, *, now):
        """Call the registered AWS API adapter here; never accept an uploaded report."""
        from adapters.aws.security_monitor import CloudTrailSecretAccessMonitor

        if not isinstance(monitor, CloudTrailSecretAccessMonitor):
            raise ValueError("Registered AWS CloudTrail collector required")
        observation = monitor.observe(now=now)
        results = []
        for item in observation["matching_successful_events"]:
            results.append(
                self.route(
                    "forbidden_secret_read",
                    event_id=item["event_id"],
                    observed_at=item["occurred_at"],
                    now=now,
                    evidence_digest=hashlib.sha256(canonical_signal(observation)).hexdigest(),
                )
            )
        denied = observation.get("matching_denied_events", [])
        if len(denied) >= 3:
            results.append(
                self.route(
                    "repeated_auth_denials",
                    event_id=denied[-1]["event_id"],
                    observed_at=denied[-1]["occurred_at"],
                    now=now,
                    evidence_digest=hashlib.sha256(canonical_signal(observation)).hexdigest(),
                )
            )
        return {
            "observations": results,
            "collection_complete": observation["collection_complete"],
            "absence_of_compromise_proven": False,
            "automatic_release_permitted": False,
        }

    def collect_inventory(self, monitor, kind, registration, *, now):
        from adapters.aws.security_inventory import NativeSecurityInventory

        if not isinstance(monitor, NativeSecurityInventory) or kind not in {
            "iam",
            "image",
            "capacity",
            "flow",
        }:
            raise ValueError("Registered native security inventory required")
        observation = getattr(monitor, "observe_" + kind)(registration, now=now)
        results = [
            self.route(
                item["kind"],
                event_id=item["event_id"],
                observed_at=item["observed_at"],
                now=now,
                evidence_digest=item["evidence_digest"],
            )
            for item in observation["events"]
        ]
        return {
            "observations": results,
            "collection_complete": observation["collection_complete"],
            "absence_of_compromise_proven": False,
            "automatic_release_permitted": False,
        }
