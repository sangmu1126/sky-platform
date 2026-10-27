"""Separate administrator consent for building a reviewed source snapshot."""

from dataclasses import asdict
from datetime import datetime, timedelta

from application.incident_source_review import FIELD
from application.security_hold import validate_release_request
from domain.access import Principal, Role
from ports.artifacts import SourceArtifact
from ports.remote_builds import BuildSettings, digest
from ports.source_build_approvals import validate_source_build_approval
from ports.state import RecordConflict


class IncidentSourceBuildApproval:
    def __init__(self, reviews, ledger, settings, *, clock, reviewer):
        self.reviews, self.ledger, self.settings = reviews, ledger, settings
        self.clock, self.reviewer = clock, reviewer

    def _snapshot(self, actor, job_id, options):
        return self.reviews._snapshot(actor, job_id, options)

    def _load(self, actor, job_id, approval_id, options):
        snapshot = self._snapshot(actor, job_id, options)
        approval = validate_source_build_approval(self.ledger.load(actor, approval_id))
        if (
            approval["organization_id"],
            approval["application_id"],
            approval["job_id"],
            approval["incident_id"],
            approval["boundary_id"],
        ) != (
            actor.organization_id,
            snapshot.record["application_id"],
            job_id,
            options["incident_id"],
            options["expected_boundary"],
        ):
            raise ValueError("Exact current incident build approval required")
        return snapshot, approval

    def approve(self, actor, job_id, *, review_id, approval_id, build_id, review_ref, seconds=900, **options):
        started = self.clock()
        validate_release_request(
            options["incident_id"],
            review_ref,
            options["expected_revision"],
            options["expected_boundary"],
            started,
        )
        if (
            type(seconds) is not int
            or not 1 <= seconds <= 900
            or not isinstance(self.settings, BuildSettings)
        ):
            raise ValueError("Bounded build consent with pinned builder required")
        snapshot, source_review, candidate = self.reviews._review(actor, job_id, review_id, options)
        expiry = min(
            datetime.fromisoformat(started) + timedelta(seconds=seconds),
            datetime.fromisoformat(source_review["expires_at"]),
        )
        approval = {
            "version": 1,
            "scope": "prepare_reviewed_source_build_only",
            "id": approval_id,
            "build_id": build_id,
            "job_id": job_id,
            "organization_id": actor.organization_id,
            "application_id": snapshot.record["application_id"],
            "incident_id": options["incident_id"],
            "boundary_id": options["expected_boundary"],
            "source_review_id": review_id,
            "source_review_digest": digest(source_review),
            "metadata_revision": snapshot.revision,
            "job_digest": digest(snapshot.record),
            "candidate": candidate.record(),
            "builder": asdict(self.settings),
            "approved_by": actor.user_id,
            "review_ref": review_ref,
            "approved_at": started,
            "expires_at": expiry.isoformat(),
            "revoked_at": None,
            "revoked_by": None,
            "revocation_ref": None,
        }
        validate_source_build_approval(approval)
        self.reviews.check(actor, job_id, review_id=review_id, candidate=candidate, **options)
        now = datetime.fromisoformat(self.clock())
        if not datetime.fromisoformat(started) <= now < expiry or now > datetime.fromisoformat(
            started
        ) + timedelta(seconds=300):
            raise ValueError("Build consent expired during source verification")
        if self._snapshot(actor, job_id, options) != snapshot:
            raise RecordConflict("Source review changed before build consent")
        self.ledger.create(actor, approval, snapshot)
        return self._report(approval, "approved", changed=True)

    def check(self, actor, job_id, *, approval_id, **options):
        started = datetime.fromisoformat(self.clock())
        snapshot, approval = self._load(actor, job_id, approval_id, options)

        def guard():
            current = self._snapshot(actor, job_id, options)
            stored = self.ledger.load(actor, approval_id)
            reviewer = self.reviewer(approval["approved_by"])
            final = self._snapshot(actor, job_id, options)
            now = datetime.fromisoformat(self.clock())
            if (
                not isinstance(reviewer, Principal)
                or reviewer.user_id != approval["approved_by"]
                or reviewer.organization_id != actor.organization_id
                or reviewer.role is not Role.ADMIN
            ):
                raise PermissionError("Build approver must remain a current administrator")
            if (
                current != snapshot
                or final != snapshot
                or approval["revoked_at"] is not None
                or approval["metadata_revision"] != snapshot.revision
                or approval["job_digest"] != digest(snapshot.record)
                or approval["source_review_digest"] != digest(snapshot.record.get(FIELD))
                or self.settings is None
                or approval["builder"] != asdict(self.settings)
                or not datetime.fromisoformat(approval["approved_at"])
                <= now
                < datetime.fromisoformat(approval["expires_at"])
                or stored != approval
                or not started <= now <= started + timedelta(seconds=300)
            ):
                raise RecordConflict("Build approval expired, revoked or binding changed")

        guard()
        self.reviews.check(
            actor,
            job_id,
            review_id=approval["source_review_id"],
            candidate=SourceArtifact.from_record(approval["candidate"]),
            **options,
        )
        guard()
        return self._report(approval, "binding_rechecked", changed=False)

    def inspect(self, actor, job_id, *, approval_id, **options):
        snapshot, approval = self._load(actor, job_id, approval_id, options)
        now = datetime.fromisoformat(self.clock())
        if now < datetime.fromisoformat(approval["approved_at"]):
            raise ValueError("Inspection precedes build consent")
        status = (
            "revoked"
            if approval["revoked_at"]
            else "expired"
            if now >= datetime.fromisoformat(approval["expires_at"])
            else "approved"
        )
        if self._snapshot(actor, job_id, options) != snapshot:
            raise RecordConflict("Incident changed during build consent inspection")
        return {
            **self._report(approval, status, changed=False),
            "source_binding_current": approval["metadata_revision"] == snapshot.revision
            and approval["job_digest"] == digest(snapshot.record),
        }

    def revoke(self, actor, job_id, *, approval_id, review_ref, **options):
        now = self.clock()
        validate_release_request(
            options["incident_id"],
            review_ref,
            options["expected_revision"],
            options["expected_boundary"],
            now,
        )
        snapshot, approval = self._load(actor, job_id, approval_id, options)
        updated = self.ledger.revoke(actor, approval, snapshot, now=now, review_ref=review_ref)
        return self._report(updated, "revoked", changed=True)

    @staticmethod
    def _report(approval, status, *, changed):
        return {
            "approval_id": approval["id"],
            "build_id": approval["build_id"],
            "source_review_id": approval["source_review_id"],
            "metadata_revision": approval["metadata_revision"],
            "expires_at": approval["expires_at"],
            "status": status,
            "build_consent_recorded": True,
            "execution_authorized": False,
            "dispatch_requested": False,
            "recovery_authorized": False,
            "hold_released": False,
            "image_safety_verified": False,
            "state_changed": changed,
            "read_only": not changed,
        }
