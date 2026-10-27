"""Separate single-use recovery approval; original artifact reviews grant no execution.

Only unchanged reviewed source/image recovery is supported. A suspected bad
artifact needs a new clean-source build admission, not this credential workflow.
"""

import re
from copy import deepcopy
from datetime import datetime, timedelta

from application.incident_artifact_review import FIELD as ARTIFACT_REVIEW
from application.incident_runtime_inspection import IncidentRuntimeInspection
from application.security_hold import validate_release_request
from domain.access import Principal, Role
from ports.remote_builds import digest
from ports.state import RecordConflict

FIELD = "security_recovery"


def base_digest(job):
    return digest({key: value for key, value in job.items() if key != FIELD})


class IncidentRecovery:
    def __init__(self, records, prerequisites, reviews, runtime, completion, *, clock, revalidate, reviewer):
        self.scope = IncidentRuntimeInspection(records, None, clock=clock, revalidate=revalidate)
        self.writer = self.scope.writer
        self.prerequisites, self.reviews, self.runtime, self.completion = (
            prerequisites,
            reviews,
            runtime,
            completion,
        )
        self.clock, self.reviewer = clock, reviewer

    def _snapshot(self, principal, job_id, options):
        now = self.clock()
        validate_release_request(
            options["incident_id"],
            "incident-recovery",
            options["expected_revision"],
            options["expected_boundary"],
            now,
        )
        snapshot = self.scope._scope(
            principal, job_id, options["incident_id"], options["expected_boundary"], now
        )
        if snapshot.revision != options["expected_revision"]:
            raise RecordConflict("Incident changed since recovery review")
        if snapshot.record.get("security_recovery_source_review") is not None:
            raise ValueError("New-source review cannot reuse unchanged-image recovery approval")
        if snapshot.record["security_hold"]["reason"] != "credential_exposure":
            raise ValueError(
                "This workflow only restores reviewed unchanged artifacts after credential exposure"
            )
        verification = snapshot.record.get("security_database_verification")
        if not isinstance(verification, dict) or verification.get("phase") != "verified_restricted":
            raise ValueError("Verified restricted credential and integrity baseline required")
        receipt = verification.get("receipt", {})
        if (
            any(
                receipt.get(k) is not True
                for k in ("authentication_verified", "previous_password_rejected", "baseline_matched")
            )
            or receipt.get("credentials_activated") is not False
            or receipt.get("login_enabled") is not False
        ):
            raise ValueError("Exact restricted verification receipt required")
        return snapshot

    def approve(self, principal, job_id, *, recovery_id, review_id, approval_ref, seconds=300, **options):
        started = self.clock()
        if (
            not isinstance(recovery_id, str)
            or not re.fullmatch(r"[a-f0-9]{32}", recovery_id)
            or type(seconds) is not int
            or not 1 <= seconds <= 900
        ):
            raise ValueError("Bounded single-use recovery identity and lifetime required")
        validate_release_request(
            options["incident_id"],
            approval_ref,
            options["expected_revision"],
            options["expected_boundary"],
            started,
        )
        snapshot = self._snapshot(principal, job_id, options)
        if snapshot.record.get(FIELD) is not None:
            raise ValueError("Existing recovery requires inspection, not another approval")
        base_options = {k: options[k] for k in ("incident_id", "expected_boundary", "expected_revision")}
        self.prerequisites._current(principal, job_id, base_options)
        checked = self.reviews.check(principal, job_id, review_id=review_id, **options)
        if (
            checked.get("artifact_review_matched") is not True
            or checked.get("recovery_authorized") is not False
        ):
            raise ValueError("Artifact review must be distinct from recovery authorization")

        def guard():
            if self._snapshot(principal, job_id, options) != snapshot:
                raise RecordConflict("Incident changed during recovery candidate preflight")

        plan = self.runtime.preflight(deepcopy(snapshot.record), recovery_id, guard=guard)
        review = snapshot.record[ARTIFACT_REVIEW]
        if (
            plan.get("image") != review["binding"]["image"]
            or plan.get("candidate_version_id")
            != snapshot.record["security_database_verification"]["candidate_version_id"]
        ):
            raise ValueError("Recovery plan differs from reviewed image or verified credential")
        guard()
        self.reviews.check(principal, job_id, review_id=review_id, **options)
        now = datetime.fromisoformat(self.clock())
        expiry = min(now + timedelta(seconds=seconds), datetime.fromisoformat(review["expires_at"]))
        if now >= expiry:
            raise ValueError("Recovery approval already expired")
        record = {
            "version": 1,
            "id": recovery_id,
            "phase": "approved",
            "incident_id": options["incident_id"],
            "boundary_id": options["expected_boundary"],
            "approved_by": principal.user_id,
            "approval_ref": approval_ref,
            "approved_at": now.isoformat(),
            "expires_at": expiry.isoformat(),
            "approved_metadata_revision": snapshot.revision + 1,
            "base_digest": base_digest(snapshot.record),
            "plan": deepcopy(plan),
            "plan_digest": digest(plan),
            "artifact_review_id": review_id,
            "artifact_binding": deepcopy(review["binding"]),
        }
        self.writer.patch(principal, job_id, snapshot.revision, {FIELD: record})
        return {
            "recovery_id": recovery_id,
            "phase": "approved",
            "metadata_revision": snapshot.revision + 1,
            "expires_at": record["expires_at"],
            "execution_started": False,
            "hold_released": False,
        }

    def execute(self, principal, job_id, *, recovery_id, **options):
        started = self.clock()
        snapshot = self._snapshot(principal, job_id, options)
        approved = snapshot.record.get(FIELD)
        if (
            not isinstance(approved, dict)
            or approved.get("id") != recovery_id
            or approved.get("phase") != "approved"
            or approved.get("approved_metadata_revision") != snapshot.revision
            or approved.get("base_digest") != base_digest(snapshot.record)
            or approved.get("plan_digest") != digest(approved.get("plan"))
            or (approved.get("incident_id"), approved.get("boundary_id"))
            != (options["incident_id"], options["expected_boundary"])
        ):
            raise ValueError("Exact unused current recovery approval required")
        plan = deepcopy(approved["plan"])

        def membership_and_expiry():
            now = datetime.fromisoformat(self.clock())
            reviewer = self.reviewer(approved["approved_by"])
            if (
                not isinstance(reviewer, Principal)
                or reviewer.user_id != approved["approved_by"]
                or reviewer.organization_id != principal.organization_id
                or reviewer.role is not Role.ADMIN
            ):
                raise PermissionError("Recovery approver must remain a current administrator")
            original = self.reviewer(snapshot.record[ARTIFACT_REVIEW]["approved_by"])
            if (
                not isinstance(original, Principal)
                or original.organization_id != principal.organization_id
                or original.user_id != snapshot.record[ARTIFACT_REVIEW]["approved_by"]
                or original.role is not Role.ADMIN
            ):
                raise PermissionError("Artifact reviewer must remain a current administrator")
            if not datetime.fromisoformat(started) <= now < datetime.fromisoformat(approved["expires_at"]):
                raise ValueError("Unexpired one-shot recovery approval required")

        membership_and_expiry()
        base_options = {k: options[k] for k in ("incident_id", "expected_boundary", "expected_revision")}
        self.prerequisites._current(principal, job_id, base_options)
        # Own approval adds one CAS revision. Recheck the native combined proof
        # against its original binding, rather than weaken artifact-review checks
        # to ignore arbitrary metadata revisions.
        _, binding, _ = self.reviews._inspect(principal, job_id, snapshot, options, started)
        if binding != approved["artifact_binding"]:
            raise ValueError("Recovery build or signing key differs from approved candidate")

        def before():
            membership_and_expiry()
            if self._snapshot(principal, job_id, options) != snapshot:
                raise RecordConflict("Recovery approval changed before consumption")

        if self.runtime.preflight(deepcopy(snapshot.record), recovery_id, guard=before) != plan:
            raise ValueError("Registered recovery runtime configuration changed")
        before()
        running = {**approved, "phase": "running", "started_at": self.clock(), "external_pending": True}
        self.writer.patch(principal, job_id, snapshot.revision, {FIELD: running})
        live_options = {**options, "expected_revision": snapshot.revision + 1}

        def guard():
            membership_and_expiry()
            current = self._snapshot(principal, job_id, live_options)
            if current.record.get(FIELD) != running or base_digest(current.record) != approved["base_digest"]:
                raise RecordConflict("Recovery execution ownership changed")
            return current

        completion_started = False
        try:
            guard()
            self.runtime.activate(plan, guard=guard)
            submitted = self.runtime.deploy(plan, guard=guard)
            result = self.runtime.verify(plan, submitted, guard=guard)
            guard()
            if (
                not isinstance(result, dict)
                or result.get("image") != plan["image"]
                or result.get("verification", {}).get("http") != "verified"
                or result.get("verification", {}).get("database_authentication") != "verified"
            ):
                raise ValueError("Actual candidate HTTP and workload authentication verification required")
            current = guard()
            _, final_binding, _ = self.reviews._inspect(
                principal, job_id, current, live_options, self.clock()
            )
            if final_binding != approved["artifact_binding"]:
                raise ValueError("Recovery artifact changed before final publication")
            verified = {
                **running,
                "phase": "verified",
                "external_pending": False,
                "verified_at": self.clock(),
                "result": deepcopy(result),
            }
            current = guard()
            self.writer.patch(principal, job_id, current.revision, {FIELD: verified})
            membership_and_expiry()
            # This transaction updates runtime metadata, archives the incident,
            # invalidates old operation leases and releases the app barrier together.
            completion_started = True
            return self.completion.complete_recovery(
                principal,
                job_id,
                incident_id=options["incident_id"],
                expected_boundary=options["expected_boundary"],
                expected_revision=current.revision + 1,
                recovery_id=recovery_id,
            )
        except Exception:  # noqa: BLE001 -- retain one-shot ownership and suppress native credentials
            if completion_started:
                raise OSError(
                    "Recovery commit outcome requires inspection; do not stop or replay a possibly committed runtime"
                ) from None
            compensation = {"confirmed": False}
            try:
                compensation = self.runtime.restrict(plan)
            except Exception:  # noqa: BLE001,S110 -- never replay activation when compensation is uncertain
                pass
            try:
                current = self.writer.snapshot(principal, job_id)
                value = current.record.get(FIELD)
                if (
                    isinstance(value, dict)
                    and value.get("id") == recovery_id
                    and value.get("phase") in {"running", "verified"}
                ):
                    self.writer.patch(
                        principal,
                        job_id,
                        current.revision,
                        {FIELD: {**value, "phase": "needs_attention", "compensation": compensation}},
                    )
            except Exception:  # noqa: BLE001,S110 -- original durable execution intent is retained
                pass
            raise OSError(
                "Recovery outcome requires inspection; execution is not automatically retried"
            ) from None
