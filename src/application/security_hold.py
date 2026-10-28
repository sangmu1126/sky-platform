"""Trusted operator hold for promotion workflows, not attack detection or quarantine.

No network, credential revocation or workload migration occurs here. Clearing a
hold after a real incident requires a separate recovery workflow. Only an explicit
operator false-positive review may clear it; ordinary approvals never do. Legacy records without a hold do not attest to safety.
"""

import re
from copy import deepcopy
from datetime import datetime, timedelta
from uuid import uuid4

from application.deployment_writes import DeploymentMetadataWriter
from domain.access import Principal, Role

REASONS = frozenset({"suspected_compromise", "credential_exposure", "untrusted_artifact"})


def require_no_security_hold(job):
    if (
        job.get("security_recovery_source_review") is not None
        or job.get("security_recovery_source_review_history") is not None
    ):
        raise ValueError("New-source review is not execution or security clearance")
    if job.get("security_recovery") is not None:
        raise ValueError("Single-use incident recovery requires its dedicated execution boundary")
    if (
        job.get("security_runtime_retirement") is not None
        or job.get("security_database_verification") is not None
    ):
        raise ValueError("Incident recovery controls require dedicated recovery")
    if job.get("security_execution_fence") is not None:
        raise ValueError("Execution fencing requires dedicated incident recovery")
    if job.get("security_artifact_review") is not None:
        raise ValueError("Artifact review requires dedicated recovery and cannot resume execution")
    if job.get("security_secret_access_fence") is not None:
        raise ValueError("Secret access fencing requires dedicated incident recovery")
    if job.get("security_runtime_containment") is not None:
        raise ValueError("Runtime containment requires dedicated incident recovery")
    # Malformed/non-null values also block. Absence preserves legacy behavior,
    # and is deliberately not interpreted as a clean security assessment.
    if (
        job.get("security_database_restriction") is not None
        or job.get("security_credential_preparation") is not None
    ):
        raise ValueError("Database restriction requires dedicated incident recovery")
    if job.get("security_hold") is not None:
        raise ValueError("Security hold blocks promotion; operator incident review is required")


def validate_hold_request(incident_id, reason, now):
    if not isinstance(incident_id, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", incident_id
    ):
        raise ValueError("A bounded incident reference is required")
    if not isinstance(reason, str) or reason not in REASONS:
        raise ValueError("A supported security hold reason is required")
    try:
        stamp = datetime.fromisoformat(now)
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise ValueError()
    except (TypeError, ValueError):
        raise ValueError("A timezone-aware incident time is required") from None
    return stamp.isoformat()


class SecurityHold:
    def __init__(self, records):
        self.writer = DeploymentMetadataWriter(records)

    def place(self, principal, job_id, *, incident_id, reason, now, expected_revision=None):
        if not isinstance(principal, Principal) or principal.role is not Role.ADMIN:
            raise PermissionError("Only an organization administrator may record a security hold")
        recorded_at = validate_hold_request(incident_id, reason, now)
        snapshot = self.writer.snapshot(principal, job_id)
        previous = snapshot.record.get("security_hold")
        if previous is not None:
            if (
                isinstance(previous, dict)
                and previous.get("incident_id") == incident_id
                and previous.get("reason") == reason
            ):
                return deepcopy(previous)
            raise ValueError("An existing security hold requires operator review")
        if expected_revision is not None and (
            type(expected_revision) is not int or snapshot.revision != expected_revision
        ):
            raise ValueError("Security signal no longer matches the current deployment record")
        hold = {
            "incident_id": incident_id,
            "reason": reason,
            "recorded_at": recorded_at,
            "recorded_by": principal.user_id,
        }
        self.writer.patch(
            principal,
            job_id,
            snapshot.revision,
            {
                "security_hold": hold,
                "promotion_automation_consent": None,
                "security_review_boundary": {"id": uuid4().hex, "recorded_at": recorded_at},
            },
        )
        return deepcopy(hold)

    def release_false_positive(
        self, principal, job_id, *, incident_id, review_ref, expected_revision, expected_boundary, now
    ):
        """Record an operator judgement, not an automated security clearance.

        No credential restoration or automation opt-in. Rotate the observation
        boundary so even the pre-release availability check cannot resume work.
        """
        if not isinstance(principal, Principal) or principal.role is not Role.ADMIN:
            raise PermissionError("Only an organization administrator may review a false positive")
        validate_release_request(incident_id, review_ref, expected_revision, expected_boundary, now)
        snapshot = self.writer.snapshot(principal, job_id)
        job = snapshot.record
        if (
            job.get("security_recovery_source_review") is not None
            or job.get("security_recovery_source_review_history") is not None
        ):
            raise ValueError("New-source review cannot be cleared by false-positive release")
        if job.get("security_artifact_review") is not None:
            raise ValueError("Artifact review requires dedicated recovery, not false-positive release")
        if job.get("security_secret_access_fence") is not None:
            raise ValueError(
                "Secret access fencing requires dedicated incident recovery, not false-positive release"
            )
        if job.get("security_runtime_containment") is not None:
            raise ValueError(
                "Runtime containment requires dedicated incident recovery, not false-positive release"
            )
        if (
            job.get("security_database_restriction") is not None
            or job.get("security_credential_preparation") is not None
        ):
            raise ValueError(
                "Database restriction requires dedicated incident recovery, not false-positive release"
            )
        if job.get("security_execution_fence") is not None:
            raise ValueError("Execution fencing requires dedicated recovery, not false-positive release")
        if (
            job.get("security_runtime_retirement") is not None
            or job.get("security_database_verification") is not None
        ):
            raise ValueError("Incident recovery controls cannot be cleared by false-positive release")
        if job.get("security_recovery") is not None:
            raise ValueError("Incident recovery cannot be cleared by false-positive release")
        history = job.get("security_hold_history", [])
        if not isinstance(history, list) or any(not _valid_release(item) for item in history):
            raise ValueError("Invalid security hold audit history")
        hold = job.get("security_hold")
        if hold is None and history:
            previous = history[-1]
            if (
                previous["hold"]["incident_id"] == incident_id
                and previous["review_ref"] == review_ref
                and previous["released_by"] == principal.user_id
                and previous["prior_metadata_revision"] == expected_revision
                and previous["prior_boundary"] == expected_boundary
                and job.get("security_review_boundary") == previous["new_boundary"]
            ):
                return deepcopy(previous)
        if snapshot.revision != expected_revision:
            from ports.state import RecordConflict

            raise RecordConflict("Deployment changed since incident review")
        if not _valid_hold(hold) or hold["incident_id"] != incident_id:
            raise ValueError("The reviewed security hold is missing or changed")
        if len(history) >= 20:
            raise ValueError("Security audit history must be archived before another release")
        from application.operating_review import deployment_observation_binding

        binding = deployment_observation_binding(job)
        boundary = job.get("security_review_boundary")
        if (
            not isinstance(boundary, dict)
            or boundary["id"] != expected_boundary
            or boundary["recorded_at"] != hold["recorded_at"]
        ):
            raise ValueError("The reviewed incident boundary changed or is missing")
        if (
            job.get("status") != "succeeded"
            or job.get("deployment_state", "active") != "active"
            or not isinstance(job.get("result"), dict)
            or not job["result"]
            or job.get("release_rollback_state") in {"running", "needs_attention"}
        ):
            raise ValueError("Only an active settled deployment may be reviewed")
        health = self.writer.health_snapshot(principal, job_id)
        observation = health.record[-1] if health and health.record else {}
        stamp = datetime.fromisoformat(now)
        try:
            checked = datetime.fromisoformat(observation["checked_at"])
            valid_time = datetime.fromisoformat(
                boundary["recorded_at"]
            ) <= checked <= stamp and stamp - checked <= timedelta(seconds=300)
        except (KeyError, TypeError, ValueError):
            valid_time = False
        if (
            observation.get("healthy") is not True
            or not isinstance(observation.get("reason"), str)
            or not observation["reason"].strip()
            or not valid_time
            or observation.get("deployment_binding") != binding
        ):
            raise ValueError("A fresh incident-bound healthy observation is required")
        released_at = stamp.isoformat()
        release = {
            "hold": deepcopy(hold),
            "outcome": "false_positive",
            "review_ref": review_ref,
            "released_by": principal.user_id,
            "released_at": released_at,
            "prior_boundary": expected_boundary,
            "prior_metadata_revision": expected_revision,
            "health_revision": health.revision,
            "new_boundary": {"id": uuid4().hex, "recorded_at": released_at},
        }
        if not _valid_release(release):
            raise ValueError("Invalid false-positive review record")
        self.writer.patch(
            principal,
            job_id,
            expected_revision,
            {
                "security_hold": None,
                "security_hold_history": history + [release],
                "security_review_boundary": release["new_boundary"],
                "promotion_automation_consent": None,
            },
        )
        return deepcopy(release)

    def status(self, principal, job_id):
        if not isinstance(principal, Principal) or principal.role is not Role.ADMIN:
            raise PermissionError("Only an organization administrator may inspect a security hold")
        snapshot = self.writer.snapshot(principal, job_id)
        return {
            "job_id": job_id,
            "metadata_revision": snapshot.revision,
            "review_boundary": deepcopy(snapshot.record["security_review_boundary"])
            if _valid_boundary(snapshot.record.get("security_review_boundary"))
            else None,
            **security_hold_projection(snapshot.record, include_details=True),
        }


def validate_release_request(incident_id, review_ref, expected_revision, expected_boundary, now):
    validate_hold_request(incident_id, "suspected_compromise", now)
    if (
        not isinstance(review_ref, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", review_ref)
        or type(expected_revision) is not int
        or not 1 <= expected_revision < 9223372036854775807
        or not isinstance(expected_boundary, str)
        or not re.fullmatch(r"[a-f0-9]{32}", expected_boundary)
    ):
        raise ValueError("An exact incident revision, boundary and bounded review reference are required")


def _valid_hold(hold):
    if not isinstance(hold, dict) or set(hold) != {"incident_id", "reason", "recorded_at", "recorded_by"}:
        return False
    try:
        validate_hold_request(hold["incident_id"], hold["reason"], hold["recorded_at"])
        return (
            isinstance(hold["recorded_by"], str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", hold["recorded_by"]) is not None
        )
    except (ValueError, TypeError):
        return False


def _valid_boundary(value):
    if (
        not isinstance(value, dict)
        or set(value) != {"id", "recorded_at"}
        or not isinstance(value["id"], str)
        or not re.fullmatch(r"[a-f0-9]{32}", value["id"])
    ):
        return False
    try:
        stamp = datetime.fromisoformat(value["recorded_at"])
        return stamp.tzinfo is not None and stamp.utcoffset() is not None
    except (TypeError, ValueError):
        return False


def _valid_release(value):
    if not isinstance(value, dict) or set(value) != {
        "hold",
        "outcome",
        "review_ref",
        "released_by",
        "released_at",
        "prior_boundary",
        "prior_metadata_revision",
        "health_revision",
        "new_boundary",
    }:
        return False
    try:
        validate_release_request(
            value["hold"]["incident_id"],
            value["review_ref"],
            value["prior_metadata_revision"],
            value["prior_boundary"],
            value["released_at"],
        )
        boundary = value["new_boundary"]
        return (
            _valid_hold(value["hold"])
            and value["outcome"] == "false_positive"
            and type(value["health_revision"]) is int
            and value["health_revision"] >= 1
            and isinstance(value["released_by"], str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", value["released_by"]) is not None
            and isinstance(boundary, dict)
            and set(boundary) == {"id", "recorded_at"}
            and isinstance(boundary["id"], str)
            and re.fullmatch(r"[a-f0-9]{32}", boundary["id"]) is not None
            and boundary["recorded_at"] == value["released_at"]
        )
    except (KeyError, TypeError, ValueError):
        return False


def security_hold_projection(job, *, include_details=False):
    hold = job.get("security_hold")
    value = {
        "status": "not_recorded" if hold is None else "held",
        "promotion_blocked": hold is not None,
        "hold": None,
    }
    if hold is not None and include_details:
        value["record_valid"] = _valid_hold(hold)
        if value["record_valid"]:
            value["hold"] = deepcopy(hold)
    history = job.get("security_hold_history")
    if (
        hold is None
        and isinstance(history, list)
        and history
        and _valid_release(history[-1])
        and job.get("security_review_boundary") == history[-1]["new_boundary"]
    ):
        value["status"] = "released_false_positive"
        if include_details:
            value["release"] = deepcopy(history[-1])
    if (
        job.get("security_database_restriction") is not None
        or job.get("security_credential_preparation") is not None
        or job.get("security_runtime_containment") is not None
    ):
        value["promotion_blocked"] = True
        value["status"] = "database_restriction_review_required"
    if job.get("security_runtime_containment") is not None:
        value["status"] = "runtime_containment_review_required"
    if job.get("security_secret_access_fence") is not None:
        value["promotion_blocked"] = True
        value["status"] = "secret_access_review_required"
    if job.get("security_artifact_review") is not None:
        value["promotion_blocked"] = True
        if value["status"] in {"not_recorded", "held", "released_false_positive"}:
            value["status"] = "artifact_review_requires_recovery"
    if job.get("security_execution_fence") is not None:
        value["promotion_blocked"] = True
        value["status"] = "execution_fence_review_required"
    if (
        job.get("security_runtime_retirement") is not None
        or job.get("security_database_verification") is not None
    ):
        value["promotion_blocked"] = True
        value["status"] = "incident_recovery_review_required"
    if job.get("security_recovery") is not None:
        value["promotion_blocked"] = True
        value["status"] = "incident_recovery_review_required"
    if (
        job.get("security_recovery_source_review") is not None
        or job.get("security_recovery_source_review_history") is not None
    ):
        value["promotion_blocked"] = True
        value["status"] = "new_source_review_requires_recovery"
    return value
