"""Review a different source snapshot without changing the held deployment.

Snapshot integrity is not code safety, build admission or recovery authorization.
"""

import re
from datetime import datetime, timedelta

from application.incident_runtime_inspection import IncidentRuntimeInspection
from application.security_hold import validate_release_request
from domain.access import Principal, Role
from ports.artifacts import SourceArtifact
from ports.remote_builds import digest
from ports.state import RecordConflict

FIELD = "security_recovery_source_review"
HISTORY = "security_recovery_source_review_history"
MAX_HISTORY = 8


def parent_digest(job):
    return digest({k: v for k, v in job.items() if k != FIELD})


def validate_review(value):
    fields = {
        "version",
        "scope",
        "id",
        "job_id",
        "incident_id",
        "boundary_id",
        "approved_by",
        "review_ref",
        "approved_at",
        "expires_at",
        "prior_metadata_revision",
        "approved_metadata_revision",
        "parent_digest",
        "prior_source_digest",
        "candidate",
        "candidate_revision",
        "revoked_at",
        "revoked_by",
        "revocation_ref",
    }
    if isinstance(value, dict) and type(value.get("version")) is int and value["version"] == 2:
        fields |= {"supersedes_review_id", "history_digest"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Exact new-source review record required")
    validate_release_request(
        value["incident_id"],
        value["review_ref"],
        value["prior_metadata_revision"],
        value["boundary_id"],
        value["approved_at"],
    )
    candidate = SourceArtifact.from_record(value["candidate"])
    if (
        type(value["version"]) is not int
        or value["version"] not in {1, 2}
        or value["scope"] != "review_new_source_snapshot_only"
        or candidate.kind != "original"
        or candidate.upload_id != value["candidate_revision"]
        or not isinstance(value["id"], str)
        or not re.fullmatch(r"[a-f0-9]{32}", value["id"])
        or not isinstance(value["job_id"], str)
        or not re.fullmatch(r"[a-f0-9]{16}", value["job_id"])
        or not isinstance(value["approved_by"], str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", value["approved_by"])
        or type(value["approved_metadata_revision"]) is not int
        or value["approved_metadata_revision"] != value["prior_metadata_revision"] + 1
        or any(
            not isinstance(value[k], str) or not re.fullmatch(r"[a-f0-9]{64}", value[k])
            for k in ("parent_digest", "prior_source_digest")
        )
        or candidate.source_digest == value["prior_source_digest"]
    ):
        raise ValueError("Bounded distinct-source review binding required")
    if value["version"] == 2 and (
        not isinstance(value["supersedes_review_id"], str)
        or not re.fullmatch(r"[a-f0-9]{32}", value["supersedes_review_id"])
        or not isinstance(value["history_digest"], str)
        or not re.fullmatch(r"[a-f0-9]{64}", value["history_digest"])
    ):
        raise ValueError("Exact predecessor and history binding required")
    approved, expires = (
        datetime.fromisoformat(value["approved_at"]),
        datetime.fromisoformat(value["expires_at"]),
    )
    if (
        approved.tzinfo is None
        or expires.tzinfo is None
        or not approved < expires <= approved + timedelta(seconds=900)
    ):
        raise ValueError("Bounded source review lifetime required")
    if value["revoked_at"] is None:
        if value["revoked_by"] is not None or value["revocation_ref"] is not None:
            raise ValueError("Incomplete source review revocation")
    else:
        validate_release_request(
            value["incident_id"],
            value["revocation_ref"],
            value["prior_metadata_revision"],
            value["boundary_id"],
            value["revoked_at"],
        )
        if (
            datetime.fromisoformat(value["revoked_at"]) < approved
            or not isinstance(value["revoked_by"], str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", value["revoked_by"])
        ):
            raise ValueError("Invalid source review revocation")
    return value


class IncidentSourceReview:
    def __init__(self, records, sources, *, clock, revalidate, reviewer):
        self.scope = IncidentRuntimeInspection(records, None, clock=clock, revalidate=revalidate)
        self.sources, self.clock, self.reviewer = sources, clock, reviewer

    def _snapshot(self, actor, job_id, options):
        now = self.clock()
        validate_release_request(
            options["incident_id"],
            "source-review",
            options["expected_revision"],
            options["expected_boundary"],
            now,
        )
        snapshot = self.scope._scope(actor, job_id, options["incident_id"], options["expected_boundary"], now)
        if snapshot.revision != options["expected_revision"]:
            raise RecordConflict("Source review requires the current held deployment revision")
        if snapshot.record["security_hold"]["reason"] not in {"untrusted_artifact", "suspected_compromise"}:
            raise ValueError("New-source review requires an artifact or compromise incident")
        if snapshot.record.get("security_recovery") is not None:
            raise ValueError("Existing recovery execution requires inspection before source review")
        self._history(snapshot.record, job_id)
        return snapshot

    @staticmethod
    def _history(job, job_id):
        history = job.get(HISTORY)
        current = job.get(FIELD)
        if history is None:
            if isinstance(current, dict) and current.get("version") == 2:
                raise ValueError("Successor review requires preserved history")
            return []
        if not isinstance(history, list) or not 1 <= len(history) <= MAX_HISTORY:
            raise ValueError("Bounded nonempty source review history required")
        if current is None:
            raise ValueError("Source review history requires a current review")
        seen = set()
        previous = None
        for index, item in enumerate([*history, current]):
            validate_review(item)
            artifact = SourceArtifact.from_record(item["candidate"])
            if (
                (item["job_id"], item["incident_id"], item["boundary_id"])
                != (job_id, job["security_hold"]["incident_id"], job["security_review_boundary"]["id"])
                or (artifact.organization_id, artifact.application_id)
                != (job["organization_id"], job["application_id"])
                or item["id"] in seen
            ):
                raise ValueError("Source review history scope or identity mismatch")
            if index == 0:
                if item["version"] != 1:
                    raise ValueError("Source review history root required")
            elif (
                item["version"] != 2
                or item["supersedes_review_id"] != previous["id"]
                or item["history_digest"] != digest(history[:index])
                or item["prior_metadata_revision"] < previous["approved_metadata_revision"]
                or datetime.fromisoformat(item["approved_at"])
                < datetime.fromisoformat(previous["revoked_at"] or previous["expires_at"])
            ):
                raise ValueError("Source review successor chain invalid")
            seen.add(item["id"])
            previous = item
        return history

    @staticmethod
    def _candidate(job, candidate):
        if not isinstance(candidate, SourceArtifact) or candidate.kind != "original":
            raise ValueError("Original normalized source snapshot required")
        if (candidate.organization_id, candidate.application_id) != (
            job["organization_id"],
            job["application_id"],
        ):
            raise PermissionError("Recovery source belongs to another application")
        old = job.get("source_digest")
        if (
            not isinstance(old, str)
            or not re.fullmatch(r"[a-f0-9]{64}", old)
            or old == candidate.source_digest
        ):
            raise ValueError("A distinct source tree and a recorded prior source digest are required")
        if job.get("source_ref") is not None:
            original = SourceArtifact.from_record(job["source_ref"])
            if (original.organization_id, original.application_id, original.source_digest) != (
                candidate.organization_id,
                candidate.application_id,
                old,
            ) or original.upload_id == candidate.upload_id:
                raise ValueError("Source revision must be separate from the original deployment")
        return old

    def _verify(self, actor, artifact, guard):
        guard()
        with self.sources.restore(actor, artifact):
            guard()
        guard()

    def approve(self, actor, job_id, *, candidate, review_id, review_ref, seconds=900, **options):
        return self._approve(
            actor,
            job_id,
            candidate=candidate,
            review_id=review_id,
            review_ref=review_ref,
            seconds=seconds,
            predecessor=None,
            options=options,
        )

    def supersede(
        self,
        actor,
        job_id,
        *,
        predecessor_review_id,
        candidate,
        review_id,
        review_ref,
        seconds=900,
        **options,
    ):
        if not isinstance(predecessor_review_id, str) or not re.fullmatch(
            r"[a-f0-9]{32}", predecessor_review_id
        ):
            raise ValueError("Exact predecessor review required")
        return self._approve(
            actor,
            job_id,
            candidate=candidate,
            review_id=review_id,
            review_ref=review_ref,
            seconds=seconds,
            predecessor=predecessor_review_id,
            options=options,
        )

    def _approve(self, actor, job_id, *, candidate, review_id, review_ref, seconds, predecessor, options):
        started = self.clock()
        validate_release_request(
            options["incident_id"],
            review_ref,
            options["expected_revision"],
            options["expected_boundary"],
            started,
        )
        if (
            not isinstance(review_id, str)
            or not re.fullmatch(r"[a-f0-9]{32}", review_id)
            or type(seconds) is not int
            or not 1 <= seconds <= 900
        ):
            raise ValueError("Exact source review identity and bounded lifetime required")
        snapshot = self._snapshot(actor, job_id, options)
        history = self._history(snapshot.record, job_id)
        previous = snapshot.record.get(FIELD)
        changes = {}
        if predecessor is None:
            if previous is not None:
                raise ValueError("Existing source review must be inspected, not replaced")
        else:
            previous = validate_review(previous)
            if previous["id"] != predecessor:
                raise ValueError("Exact current predecessor required")
            artifact = SourceArtifact.from_record(previous["candidate"])
            if (
                (previous["job_id"], previous["incident_id"], previous["boundary_id"])
                != (job_id, options["incident_id"], options["expected_boundary"])
                or (artifact.organization_id, artifact.application_id)
                != (actor.organization_id, snapshot.record["application_id"])
                or datetime.fromisoformat(started)
                < datetime.fromisoformat(previous["revoked_at"] or previous["expires_at"])
            ):
                raise ValueError("Predecessor must be scoped and revoked or expired")
            if len(history) >= MAX_HISTORY or review_id in {item["id"] for item in [*history, previous]}:
                raise ValueError("History capacity or single-use review identity exhausted")
            changes[HISTORY] = [*history, previous]
        prior = self._candidate(snapshot.record, candidate)
        expires = datetime.fromisoformat(started) + timedelta(seconds=seconds)

        def guard():
            instant = datetime.fromisoformat(self.clock())
            if not datetime.fromisoformat(started) <= instant < expires or instant > datetime.fromisoformat(
                started
            ) + timedelta(seconds=300):
                raise ValueError("Source review expired during verification")
            if self._snapshot(actor, job_id, options) != snapshot:
                raise RecordConflict("Incident changed during source snapshot verification")

        self._verify(actor, candidate, guard)
        now = datetime.fromisoformat(self.clock())
        beginning = datetime.fromisoformat(started)
        expires = beginning + timedelta(seconds=seconds)
        if not beginning <= now < expires or now > beginning + timedelta(seconds=300):
            raise ValueError("Source review expired during snapshot verification")
        record = {
            "version": 2 if predecessor is not None else 1,
            "scope": "review_new_source_snapshot_only",
            "id": review_id,
            "job_id": job_id,
            "incident_id": options["incident_id"],
            "boundary_id": options["expected_boundary"],
            "approved_by": actor.user_id,
            "review_ref": review_ref,
            "approved_at": started,
            "expires_at": expires.isoformat(),
            "prior_metadata_revision": snapshot.revision,
            "approved_metadata_revision": snapshot.revision + 1,
            "parent_digest": parent_digest({**snapshot.record, **changes}),
            "prior_source_digest": prior,
            "candidate": candidate.record(),
            "candidate_revision": candidate.upload_id,
            "revoked_at": None,
            "revoked_by": None,
            "revocation_ref": None,
        }
        if predecessor is not None:
            record.update(supersedes_review_id=predecessor, history_digest=digest(changes[HISTORY]))
        validate_review(record)
        self._history({**snapshot.record, **changes, FIELD: record}, job_id)
        guard()
        # Metadata CAS only: no operation/outbox, source overwrite or native execution.
        receipt = self.scope.writer.patch(actor, job_id, snapshot.revision, {**changes, FIELD: record})
        return self._report(record, receipt.revision, "review_recorded", verified=True, changed=True)

    def _review(self, actor, job_id, review_id, options):
        snapshot = self._snapshot(actor, job_id, options)
        review = validate_review(snapshot.record.get(FIELD))
        if (review["id"], review["job_id"], review["incident_id"], review["boundary_id"]) != (
            review_id,
            job_id,
            options["incident_id"],
            options["expected_boundary"],
        ):
            raise ValueError("Exact current new-source review required")
        artifact = SourceArtifact.from_record(review["candidate"])
        if (artifact.organization_id, artifact.application_id) != (
            snapshot.record["organization_id"],
            snapshot.record["application_id"],
        ):
            raise PermissionError("Stored source review belongs to another application")
        return snapshot, review, artifact

    def check(self, actor, job_id, *, review_id, candidate, **options):
        started = self.clock()
        snapshot, review, artifact = self._review(actor, job_id, review_id, options)
        if candidate != artifact:
            raise ValueError("Source configuration differs from reviewed revision")

        def guard():
            current, stored, _ = self._review(actor, job_id, review_id, options)
            reviewer = self.reviewer(review["approved_by"])
            now = datetime.fromisoformat(self.clock())
            if (
                not isinstance(reviewer, Principal)
                or reviewer.user_id != review["approved_by"]
                or reviewer.organization_id != actor.organization_id
                or reviewer.role is not Role.ADMIN
            ):
                raise PermissionError("Source reviewer must remain a current administrator")
            if self._snapshot(actor, job_id, options) != snapshot:
                raise RecordConflict("Metadata changed during reviewer validation")
            if (
                current != snapshot
                or stored != review
                or review["revoked_at"] is not None
                or current.revision != review["approved_metadata_revision"]
                or parent_digest(current.record) != review["parent_digest"]
            ):
                raise RecordConflict("New-source review revoked or metadata changed")
            if not datetime.fromisoformat(review["approved_at"]) <= now < datetime.fromisoformat(
                review["expires_at"]
            ) or not datetime.fromisoformat(started) <= now <= datetime.fromisoformat(started) + timedelta(
                seconds=300
            ):
                raise ValueError("Source review expired or inspection stale")

        guard()
        self._verify(actor, artifact, guard)
        return self._report(review, snapshot.revision, "snapshot_rechecked", verified=True, changed=False)

    def inspect(self, actor, job_id, *, review_id, **options):
        snapshot, review, _ = self._review(actor, job_id, review_id, options)
        now = datetime.fromisoformat(self.clock())
        if now < datetime.fromisoformat(review["approved_at"]):
            raise ValueError("Inspection cannot precede source review")
        status = (
            "revoked"
            if review["revoked_at"]
            else "expired"
            if now >= datetime.fromisoformat(review["expires_at"])
            else "review_recorded"
        )
        if self._snapshot(actor, job_id, options) != snapshot:
            raise RecordConflict("Source review changed during inspection")
        return {
            **self._report(review, snapshot.revision, status, verified=False, changed=False),
            "history_count": len(self._history(snapshot.record, job_id)),
            "snapshot_binding_current": snapshot.revision == review["approved_metadata_revision"]
            and parent_digest(snapshot.record) == review["parent_digest"],
        }

    def revoke(self, actor, job_id, *, review_id, review_ref, **options):
        now = self.clock()
        validate_release_request(
            options["incident_id"],
            review_ref,
            options["expected_revision"],
            options["expected_boundary"],
            now,
        )
        snapshot, review, _ = self._review(actor, job_id, review_id, options)
        if review["revoked_at"] is not None:
            raise ValueError("Source review already revoked; inspect persisted result")
        updated = {**review, "revoked_at": now, "revoked_by": actor.user_id, "revocation_ref": review_ref}
        validate_review(updated)
        if self._snapshot(actor, job_id, options) != snapshot:
            raise RecordConflict("Source review changed before revocation")
        receipt = self.scope.writer.patch(actor, job_id, snapshot.revision, {FIELD: updated})
        return self._report(updated, receipt.revision, "revoked", verified=False, changed=True)

    @staticmethod
    def _report(review, revision, status, *, verified, changed):
        return {
            "review_id": review["id"],
            "candidate_revision": review["candidate_revision"],
            "candidate_source_digest": review["candidate"]["source_digest"],
            "metadata_revision": revision,
            "status": status,
            "expires_at": review["expires_at"],
            "source_snapshot_verified": verified,
            "build_authorized": False,
            "recovery_authorized": False,
            "image_safety_verified": False,
            "credentials_activated": False,
            "hold_released": False,
            "state_changed": changed,
            "read_only": not changed,
        }
