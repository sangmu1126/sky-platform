"""Outcome equivalence review, independent of provider product names.

No SDK output or HTTP payload should be deserialized directly into this input.
Callers must resolve criteria and collectors from authorized server registries.
This review neither enables an executor nor issues migration approval.
"""

import hashlib
import json
from dataclasses import asdict
from datetime import UTC, datetime, timedelta

from domain.environment_transition import (
    PreservationObservation,
    PreservationRequirement,
    TransitionScope,
    _time,
    validate_preservation_requirements,
)


def assess_environment_transition(
    scope: TransitionScope,
    requirements: tuple[PreservationRequirement, ...],
    observations: tuple[PreservationObservation, ...],
    *,
    now: datetime,
    max_age_seconds: int = 300,
) -> dict:
    if not isinstance(scope, TransitionScope):
        raise TypeError("Typed transition scope required")
    _time(now)
    if type(max_age_seconds) is not int or not 1 <= max_age_seconds <= 300:
        raise ValueError("Bounded observation age required")
    validate_preservation_requirements(requirements)
    by_capability = {item.capability: item for item in requirements}
    if (
        not isinstance(observations, tuple)
        or len(observations) > 128
        or not all(isinstance(item, PreservationObservation) for item in observations)
    ):
        raise ValueError("Bounded immutable preservation observations required")

    indexed = {}
    for observation in observations:
        if observation.scope != scope:
            raise ValueError("Observation belongs to a different transition scope")
        if by_capability.get(observation.requirement.capability) != observation.requirement:
            raise ValueError("Observation belongs to a different preservation criterion")
        key = (observation.requirement.capability, observation.endpoint)
        if key in indexed:
            # Never choose the favourable result from conflicting evidence.
            raise ValueError("Ambiguous duplicate preservation observation")
        indexed[key] = observation

    checks = []
    for capability in sorted(by_capability):
        endpoints = {}
        for endpoint in ("source", "target"):
            observation = indexed.get((capability, endpoint))
            status, reason = "unverified", "missing_evidence"
            evidence_ref = None
            if observation is not None:
                evidence_ref = observation.evidence_ref
                if observation.origin != "collector":
                    reason = "proposal_is_not_verification"
                elif observation.observed_at > now:
                    reason = "future_evidence"
                elif now >= min(
                    observation.expires_at,
                    observation.observed_at + timedelta(seconds=max_age_seconds),
                ):
                    reason = "expired_evidence"
                elif observation.status == "unknown":
                    reason = "collector_could_not_verify"
                else:
                    status, reason = observation.status, "criterion_" + observation.status
            endpoints[endpoint] = {
                "status": status,
                "reason": reason,
                "evidence_ref": evidence_ref,
            }
        statuses = {value["status"] for value in endpoints.values()}
        status = "failed" if "failed" in statuses else "unverified"
        if statuses == {"verified"}:
            status = "verified"
        checks.append({"capability": capability, "status": status, "endpoints": endpoints})

    def stamp(value: datetime) -> str:
        return value.astimezone(UTC).isoformat()

    # Bind both endpoint revisions, every criterion and every observation,
    # including failed/unknown/proposed results. Order does not affect identity.
    serialized = []
    for item in sorted(observations, key=lambda item: (item.requirement.capability, item.endpoint)):
        payload = asdict(item)
        payload["observed_at"] = stamp(item.observed_at)
        payload["expires_at"] = stamp(item.expires_at)
        serialized.append(payload)
    report = {
        "schema_version": 1,
        "scope": asdict(scope),
        "requirements": [asdict(by_capability[key]) for key in sorted(by_capability)],
        "observations": serialized,
        "evaluated_at": stamp(now),
        "max_age_seconds": max_age_seconds,
        "status": "verified" if all(item["status"] == "verified" for item in checks) else "blocked",
        "checks": checks,
        "unresolved_capabilities": [item["capability"] for item in checks if item["status"] != "verified"],
        "approval_scope": "environment_preservation_review_only",
        "execution_authorized": False,
        "ready_to_cutover": False,
        "availability_claim": "not_assessed",
    }
    report["report_id"] = (
        "ENV-"
        + hashlib.sha256(
            json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
    )
    return report


def validate_environment_transition_report(document: dict) -> dict:
    """Recompute persisted content; this never authenticates its origin or approval.

    Only trusted collector composition may supply a report to the review store.
    Recalculation prevents stored status/check edits from suppressing unknown or
    failed observations. Freshness and membership must still be checked at use.
    """
    try:
        if not isinstance(document, dict):
            raise TypeError("Report object required")
        raw = json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(raw.encode()) > 256 * 1024:
            raise ValueError("Bounded environment report required")
        scope = TransitionScope(**document["scope"])
        requirements = tuple(PreservationRequirement(**v) for v in document["requirements"])
        observations = tuple(
            PreservationObservation(
                scope=TransitionScope(**v["scope"]),
                requirement=PreservationRequirement(**v["requirement"]),
                endpoint=v["endpoint"],
                evidence_ref=v["evidence_ref"],
                verifier_ref=v["verifier_ref"],
                observed_at=datetime.fromisoformat(v["observed_at"]),
                expires_at=datetime.fromisoformat(v["expires_at"]),
                status=v["status"],
                origin=v["origin"],
            )
            for v in document["observations"]
        )
        expected = assess_environment_transition(
            scope,
            requirements,
            observations,
            now=datetime.fromisoformat(document["evaluated_at"]),
            max_age_seconds=document["max_age_seconds"],
        )
        if json.dumps(expected, sort_keys=True, separators=(",", ":"), allow_nan=False) != raw:
            raise ValueError("Environment report contents differ from collected observations")
        return json.loads(raw)
    except (KeyError, TypeError, OverflowError, ValueError, RecursionError):
        raise ValueError("Invalid persisted environment transition report") from None
