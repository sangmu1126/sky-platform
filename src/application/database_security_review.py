"""Only current administrators enroll workload trust; source/login origin cannot."""

import re
from datetime import datetime, timedelta

from application.deployment_writes import DeploymentMetadataWriter
from domain.access import Principal, Role
from domain.database_security import assessment_digest, require_current_database_review  # noqa: F401


def review_database_security(
    records, principal, job_id, assessment, *, expected_revision, review_ref, now, seconds=3600
):
    if not isinstance(principal, Principal) or principal.role is not Role.ADMIN:
        raise PermissionError("Current administrator required to enroll database trust")
    if (
        not isinstance(assessment, dict)
        or set(assessment) != {"data_sensitivity", "tenant_trust", "physical_isolation_required"}
        or assessment["data_sensitivity"] not in {"low", "moderate", "high", "unknown"}
        or assessment["tenant_trust"] not in {"trusted", "untrusted", "unknown"}
        or type(assessment["physical_isolation_required"]) is not bool
        or type(seconds) is not int
        or not 1 <= seconds <= 86400
        or not isinstance(review_ref, str)
        or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", review_ref)
    ):
        raise ValueError("Explicit bounded operator trust assessment required")
    stamp = datetime.fromisoformat(now)
    if stamp.tzinfo is None:
        raise ValueError("Timezone-aware review required")
    writer = DeploymentMetadataWriter(records)
    snapshot = writer.snapshot(principal, job_id)
    if type(expected_revision) is not int or snapshot.revision != expected_revision:
        raise ValueError("Database trust review source/revision changed")
    job = snapshot.record
    if not isinstance(job.get("source_digest"), str) or not re.fullmatch(
        r"[0-9a-f]{64}", job["source_digest"]
    ):
        raise ValueError("Source-bound database trust review required")
    review = {
        "reviewed_by": principal.user_id,
        "organization_id": principal.organization_id,
        "application_id": job["application_id"],
        "source_digest": job["source_digest"],
        "assessment_digest": assessment_digest(assessment),
        "review_ref": review_ref,
        "reviewed_at": now,
        "expires_at": (stamp + timedelta(seconds=seconds)).isoformat(),
    }
    writer.patch(
        principal,
        job_id,
        snapshot.revision,
        {"database_security_requirements": dict(assessment), "database_security_review": review},
    )
    return review
