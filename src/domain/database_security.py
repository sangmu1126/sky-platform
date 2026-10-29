"""Pure source-bound database trust assessment validation."""

import hashlib
import json
import re
from datetime import datetime, timedelta


def assessment_digest(assessment):
    return hashlib.sha256(json.dumps(assessment, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def require_current_database_review(job, assessment, *, now):
    review = job.get("database_security_review")
    if (
        not isinstance(review, dict)
        or set(review)
        != {
            "reviewed_by",
            "organization_id",
            "application_id",
            "source_digest",
            "assessment_digest",
            "review_ref",
            "reviewed_at",
            "expires_at",
        }
        or review["organization_id"] != job.get("organization_id")
        or review["application_id"] != job.get("application_id")
        or review["source_digest"] != job.get("source_digest")
        or review["assessment_digest"] != assessment_digest(assessment)
        or not isinstance(review["reviewed_by"], str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", review["reviewed_by"])
    ):
        raise ValueError("Shared database requires a current source-bound administrator isolation review")
    stamp, start, end = (
        datetime.fromisoformat(value) for value in (now, review["reviewed_at"], review["expires_at"])
    )
    if any(t.tzinfo is None for t in (stamp, start, end)) or not start <= stamp < end <= start + timedelta(
        days=1
    ):
        raise ValueError("Shared database administrator isolation review expired or invalid")
    return review
