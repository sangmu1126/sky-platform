"""Source and ownership continuity for an explicit release transition."""

from domain.access import owner_from_record
from engine.github_release_scope import same_github_release_scope


def same_release_scope(previous, current):
    if (
        not current.get("application_id")
        or previous.get("application_id") != current.get("application_id")
        or previous.get("target") != current.get("target")
    ):
        return False
    if "github_source" in previous or "github_source" in current:
        return same_github_release_scope(previous, current)
    if any(key in job for job in (previous, current) for key in ("organization_id", "created_by")):
        old_owner, new_owner = owner_from_record(previous), owner_from_record(current)
        return (
            old_owner is not None
            and new_owner is not None
            and old_owner.organization_id == new_owner.organization_id
        )
    # Authorization for legacy local records remains the HTTP boundary's responsibility.
    return True
