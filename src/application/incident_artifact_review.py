"""Separate, expiring artifact review. No execution, hold release or credential activation."""

import re
from copy import deepcopy
from datetime import datetime, timedelta

from application.incident_runtime_inspection import IncidentRuntimeInspection
from application.security_hold import validate_release_request
from ports.remote_builds import digest
from ports.state import RecordConflict

FIELD = "security_artifact_review"
HISTORY = "security_artifact_review_history"


def metadata_digest(record):
    return digest({k: v for k, v in record.items() if k not in {FIELD, HISTORY}})


def validate_review(value):
    fields = {
        "version",
        "id",
        "scope",
        "job_id",
        "incident_id",
        "boundary_id",
        "approved_by",
        "review_ref",
        "approved_at",
        "expires_at",
        "prior_metadata_revision",
        "approved_metadata_revision",
        "metadata_digest",
        "evidence_digest",
        "binding",
        "revoked_at",
        "revoked_by",
        "revocation_ref",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Exact persisted artifact review required")
    validate_release_request(
        value["incident_id"],
        value["review_ref"],
        value["prior_metadata_revision"],
        value["boundary_id"],
        value["approved_at"],
    )
    if (
        type(value["version"]) is not int
        or value["version"] != 1
        or value["scope"] != "review_existing_build_evidence"
        or not re.fullmatch(r"[a-f0-9]{32}", value["id"] or "")
        or not re.fullmatch(r"[a-f0-9]{16}", value["job_id"] or "")
        or not isinstance(value["approved_by"], str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", value["approved_by"])
        or type(value["approved_metadata_revision"]) is not int
        or value["approved_metadata_revision"] != value["prior_metadata_revision"] + 1
        or not isinstance(value["binding"], dict)
        or any(
            not isinstance(value[k], str) or not re.fullmatch(r"[a-f0-9]{64}", value[k])
            for k in ("metadata_digest", "evidence_digest")
        )
    ):
        raise ValueError("Invalid artifact review scope or identity")
    approved, expiry = (
        datetime.fromisoformat(value["approved_at"]),
        datetime.fromisoformat(value["expires_at"]),
    )
    if expiry.tzinfo is None or not timedelta(0) < expiry - approved <= timedelta(seconds=900):
        raise ValueError("Bounded review lifetime required")
    revoked = (value["revoked_at"], value["revoked_by"], value["revocation_ref"])
    if any(v is not None for v in revoked):
        validate_release_request(
            value["incident_id"],
            value["revocation_ref"],
            value["approved_metadata_revision"],
            value["boundary_id"],
            value["revoked_at"],
        )
        if (
            not isinstance(value["revoked_by"], str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", value["revoked_by"])
            or datetime.fromisoformat(value["revoked_at"]) < approved
        ):
            raise ValueError("Invalid review revocation")
    return value


class IncidentArtifactReview:
    def __init__(self, records, inspector, *, clock, revalidate, reviewer):
        self.scope = IncidentRuntimeInspection(records, None, clock=clock, revalidate=revalidate)
        self.inspector, self.clock, self.reviewer = inspector, clock, reviewer

    def _snapshot(self, principal, job_id, options, now):
        validate_release_request(
            options["incident_id"],
            "artifact-review",
            options["expected_revision"],
            options["expected_boundary"],
            now,
        )
        snapshot = self.scope._scope(
            principal, job_id, options["incident_id"], options["expected_boundary"], now
        )
        if snapshot.revision != options["expected_revision"]:
            raise RecordConflict("Artifact review requires the current deployment revision")
        return snapshot

    def _inspect(self, principal, job_id, snapshot, options, started):
        registered_image = self.inspector.image_registration
        proof = self.inspector.inspect(principal, job_id, **options)
        if self.inspector.image_registration != registered_image:
            raise RecordConflict("Image registration changed during artifact review")
        if not isinstance(proof, dict):
            raise TypeError("Exact combined inspection required")
        completed = self.clock()
        current = self._snapshot(principal, job_id, options, completed)
        if current != snapshot:
            raise RecordConflict("Deployment changed during artifact review")
        if (
            any(
                proof.get(k) is not True
                for k in (
                    "signature_verified",
                    "expected_input_binding_matched",
                    "consumed_deployment_approval_matched",
                    "key_liveness_checked",
                    "ecr_image_verified",
                    "image_signature_approval_binding_matched",
                    "read_only",
                )
            )
            or any(
                proof.get(k) is not False
                for k in (
                    "recovery_authorized",
                    "current_approval_verified",
                    "faithful_compilation_verified",
                    "image_safety_verified",
                    "state_changed",
                )
            )
            or (proof.get("incident_id"), proof.get("boundary_id"), proof.get("metadata_revision"))
            != (options["incident_id"], options["expected_boundary"], snapshot.revision)
            or not datetime.fromisoformat(started)
            <= datetime.fromisoformat(proof["observed_at"])
            <= datetime.fromisoformat(completed)
            <= datetime.fromisoformat(started) + timedelta(seconds=300)
            or datetime.fromisoformat(proof["expires_at"]) <= datetime.fromisoformat(completed)
        ):
            raise ValueError("Fresh combined image, signing key and approval evidence required")
        r = registered_image
        binding = {
            "build_id": proof["build_id"],
            "request_digest": proof["request_digest"],
            "key_arn": proof["key_arn"],
            "public_key_fingerprint": proof["public_key_fingerprint"],
            "image": r.image,
            "config_digest": r.config_digest,
            "source_digest": r.source_digest,
            "source_revision": r.source_revision,
            "build_reference": r.build_reference,
        }
        return proof, binding, completed

    def approve(self, principal, job_id, *, review_id, review_ref, seconds=900, **options):
        started = self.clock()
        if (
            not isinstance(review_id, str)
            or not re.fullmatch(r"[a-f0-9]{32}", review_id)
            or type(seconds) is not int
            or not 1 <= seconds <= 900
        ):
            raise ValueError("Exact review ID and bounded lifetime required")
        validate_release_request(
            options["incident_id"],
            review_ref,
            options["expected_revision"],
            options["expected_boundary"],
            started,
        )
        snapshot = self._snapshot(principal, job_id, options, started)
        old = snapshot.record.get(FIELD)
        history = snapshot.record.get(HISTORY, [])
        if not isinstance(history, list) or len(history) >= 10:
            raise ValueError("Archive artifact reviews before creating another review")
        for review in history:
            validate_review(review)
        if any(review["id"] == review_id for review in history):
            raise ValueError("Review identity cannot be reused")
        if old is not None:
            validate_review(old)
            if old["id"] == review_id or (
                old["revoked_at"] is None
                and datetime.fromisoformat(started) < datetime.fromisoformat(old["expires_at"])
            ):
                raise ValueError("An existing active review must be revoked first")
            history = history + [deepcopy(old)]
        proof, binding, completed = self._inspect(principal, job_id, snapshot, options, started)
        expiry = min(
            datetime.fromisoformat(completed) + timedelta(seconds=seconds),
            datetime.fromisoformat(proof["expires_at"]),
        )
        review = {
            "version": 1,
            "id": review_id,
            "scope": "review_existing_build_evidence",
            "job_id": job_id,
            "incident_id": options["incident_id"],
            "boundary_id": options["expected_boundary"],
            "approved_by": principal.user_id,
            "review_ref": review_ref,
            "approved_at": completed,
            "expires_at": expiry.isoformat(),
            "prior_metadata_revision": snapshot.revision,
            "approved_metadata_revision": snapshot.revision + 1,
            "metadata_digest": metadata_digest(snapshot.record),
            "evidence_digest": digest(proof),
            "binding": binding,
            "revoked_at": None,
            "revoked_by": None,
            "revocation_ref": None,
        }
        validate_review(review)
        self._snapshot(principal, job_id, options, self.clock())
        if datetime.fromisoformat(self.clock()) >= expiry:
            raise ValueError("Artifact evidence expired before approval was recorded")
        written = self.scope.writer.patch(
            principal, job_id, snapshot.revision, {FIELD: review, HISTORY: history}
        )
        return self._report(review, written.revision, "approved", state_changed=True)

    def check(self, principal, job_id, *, review_id, **options):
        started = self.clock()
        snapshot = self._snapshot(principal, job_id, options, started)
        review = validate_review(snapshot.record.get(FIELD))
        if review["id"] != review_id:
            raise ValueError("Exact stored review required")
        self._usable(principal, job_id, review, snapshot, options, started)
        _, binding, completed = self._inspect(principal, job_id, snapshot, options, started)
        if binding != review["binding"]:
            raise ValueError("Artifact review does not cover this image, build or signing key")
        self._usable(principal, job_id, review, snapshot, options, completed)
        if self._snapshot(principal, job_id, options, self.clock()) != snapshot:
            raise RecordConflict("Deployment changed before artifact review result")
        return self._report(review, snapshot.revision, "rechecked", state_changed=False)

    def _usable(self, principal, job_id, review, snapshot, options, now):
        reviewer = self.reviewer(review["approved_by"])
        from domain.access import Principal, Role

        if (
            not isinstance(reviewer, Principal)
            or reviewer.user_id != review["approved_by"]
            or reviewer.organization_id != principal.organization_id
            or reviewer.role is not Role.ADMIN
        ):
            raise PermissionError("Original artifact reviewer must remain an administrator")
        if (
            (review["job_id"], review["incident_id"], review["boundary_id"])
            != (job_id, options["incident_id"], options["expected_boundary"])
            or review["revoked_at"] is not None
            or not datetime.fromisoformat(review["approved_at"])
            <= datetime.fromisoformat(now)
            < datetime.fromisoformat(review["expires_at"])
            or review["approved_metadata_revision"] != snapshot.revision
            or review["metadata_digest"] != metadata_digest(snapshot.record)
        ):
            raise ValueError("Artifact review expired, revoked or no longer matches deployment")

    def revoke(self, principal, job_id, *, review_id, review_ref, **options):
        now = self.clock()
        validate_release_request(
            options["incident_id"],
            review_ref,
            options["expected_revision"],
            options["expected_boundary"],
            now,
        )
        snapshot = self._snapshot(principal, job_id, options, now)
        review = deepcopy(validate_review(snapshot.record.get(FIELD)))
        if (review["id"], review["job_id"], review["incident_id"], review["boundary_id"]) != (
            review_id,
            job_id,
            options["incident_id"],
            options["expected_boundary"],
        ) or review["revoked_at"] is not None:
            raise ValueError("Exact unrevoked artifact review required")
        review.update(revoked_at=now, revoked_by=principal.user_id, revocation_ref=review_ref)
        validate_review(review)
        self._snapshot(principal, job_id, options, self.clock())
        written = self.scope.writer.patch(principal, job_id, snapshot.revision, {FIELD: review})
        return self._report(review, written.revision, "revoked", state_changed=True)

    @staticmethod
    def _report(review, revision, status, *, state_changed):
        return {
            "review_id": review["id"],
            "status": status,
            "metadata_revision": revision,
            "expires_at": review["expires_at"],
            "artifact_review_matched": status == "rechecked",
            "recovery_authorized": False,
            "execution_authorized": False,
            "hold_released": False,
            "credentials_activated": False,
            "state_changed": state_changed,
            "read_only": not state_changed,
        }
