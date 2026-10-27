"""Strict reviewed-source build consent, separate from execution and recovery."""

import re
from dataclasses import asdict
from datetime import datetime, timedelta
from typing import Protocol

from ports.artifacts import SourceArtifact
from ports.remote_builds import BuildSettings, canonical, identity


def validate_source_build_approval(value):
    fields = {
        "version",
        "scope",
        "id",
        "build_id",
        "job_id",
        "organization_id",
        "application_id",
        "incident_id",
        "boundary_id",
        "source_review_id",
        "source_review_digest",
        "metadata_revision",
        "job_digest",
        "candidate",
        "builder",
        "approved_by",
        "review_ref",
        "approved_at",
        "expires_at",
        "revoked_at",
        "revoked_by",
        "revocation_ref",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or type(value["version"]) is not int
        or value["version"] != 1
    ):
        raise ValueError("Exact source build approval required")
    canonical(value)
    if value["scope"] != "prepare_reviewed_source_build_only":
        raise ValueError("Separate source build consent scope required")
    for name in ("id", "boundary_id", "source_review_id"):
        if not isinstance(value[name], str) or not re.fullmatch(r"[a-f0-9]{32}", value[name]):
            raise ValueError("Exact source build identity required")
    if not isinstance(value["job_id"], str) or not re.fullmatch(r"[a-f0-9]{16}", value["job_id"]):
        raise ValueError("Exact held job required")
    identity(value["build_id"])
    for name in ("organization_id", "application_id", "approved_by"):
        if not isinstance(value[name], str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", value[name]
        ):
            raise ValueError("Exact source build owner required")
    for name in ("source_review_digest", "job_digest"):
        if not isinstance(value[name], str) or not re.fullmatch(r"[a-f0-9]{64}", value[name]):
            raise ValueError("Exact source build binding required")
    for name in ("review_ref", "incident_id"):
        if not isinstance(value[name], str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}", value[name]
        ):
            raise ValueError("Bounded operator reference required")
    if (
        type(value["metadata_revision"]) is not int
        or not 1 <= value["metadata_revision"] < 9223372036854775807
    ):
        raise ValueError("Positive source review revision required")
    artifact = SourceArtifact.from_record(value["candidate"])
    if artifact.kind != "original" or (artifact.organization_id, artifact.application_id) != (
        value["organization_id"],
        value["application_id"],
    ):
        raise ValueError("Same application original snapshot required")
    if not isinstance(value["builder"], dict):
        raise TypeError("Pinned builder configuration required")
    settings = BuildSettings(**value["builder"])
    if value["builder"] != asdict(settings):
        raise ValueError("Exact pinned builder fields required")
    times = []
    for name in ("approved_at", "expires_at"):
        if not isinstance(value[name], str):
            raise TypeError("Timezone-aware approval lifetime required")
        instant = datetime.fromisoformat(value[name])
        if instant.tzinfo is None:
            raise ValueError("Timezone-aware approval lifetime required")
        times.append(instant)
    if not times[0] < times[1] <= times[0] + timedelta(seconds=900):
        raise ValueError("Bounded build approval lifetime required")
    if value["revoked_at"] is None:
        if value["revoked_by"] is not None or value["revocation_ref"] is not None:
            raise ValueError("Incomplete source build revocation")
    else:
        if not isinstance(value["revoked_at"], str):
            raise ValueError("Invalid source build revocation time")
        revoked = datetime.fromisoformat(value["revoked_at"])
        if revoked.tzinfo is None or revoked < times[0]:
            raise ValueError("Invalid source build revocation time")
        for name in ("revoked_by", "revocation_ref"):
            if not isinstance(value[name], str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}", value[name]
            ):
                raise ValueError("Exact source build revocation required")
    return value


class SourceBuildApprovals(Protocol):
    """Atomic ledger writes lock and compare the unchanged held job snapshot.

    No implementation dispatches work. A later single-use execution admission is
    required; this record cannot be consumed by ordinary deployment approvals.
    """

    def create(self, actor, approval, snapshot): ...
    def load(self, actor, approval_id): ...
    def revoke(self, actor, approval, snapshot, *, now, review_ref): ...
