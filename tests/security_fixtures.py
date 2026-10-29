"""Explicit fixture enrollment, never production trust inferred from login/source."""

from datetime import UTC, datetime, timedelta

from domain.database_security import assessment_digest

STAMP = datetime.now(UTC)


def trusted_database_job(job):
    assessment = {"data_sensitivity": "low", "tenant_trust": "trusted", "physical_isolation_required": False}
    return {
        **job,
        "database_security_requirements": assessment,
        "database_security_review": {
            "reviewed_by": "fixture-admin",
            "organization_id": job["organization_id"],
            "application_id": job["application_id"],
            "source_digest": job["source_digest"],
            "assessment_digest": assessment_digest(assessment),
            "review_ref": "trusted-fixture",
            "reviewed_at": STAMP.isoformat(),
            "expires_at": (STAMP + timedelta(hours=1)).isoformat(),
        },
    }
