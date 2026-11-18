"""Review of metadata only; no migration execution capability is issued."""

from dataclasses import dataclass, field
from datetime import datetime


class MigrationReviewUnavailable(ValueError):
    """Review changed, expired, was revoked, or is not approved."""


@dataclass(frozen=True)
class MigrationPreflightReview:
    id: str
    plan_id: str
    evidence_id: str
    expires_at: datetime | None
    approved_by: str | None
    approval_scope: str = field(default="preflight_review_only", init=False)
    execution_authorized: bool = field(default=False, init=False)
