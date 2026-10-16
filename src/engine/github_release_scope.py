"""Conservative release lineage checks, separate from permission to deploy an app."""

import re
from collections.abc import Mapping

from domain.access import owner_from_record


def same_github_release_scope(previous: Mapping, current: Mapping) -> bool:
    """Allow replacement only within the same source and recorded ownership.

    Two legacy unowned records may match in local mode. Partial or mixed ownership
    is never inferred. This is a lineage check, not an HTTP authorization grant.
    """
    old_source, new_source = previous.get("github_source"), current.get("github_source")
    if not isinstance(old_source, Mapping) or not isinstance(new_source, Mapping):
        return False
    if (
        not isinstance(current.get("application_id"), str)
        or not current["application_id"]
        or previous.get("application_id") != current["application_id"]
    ):
        return False
    for field in ("repository_url", "branch"):
        if not isinstance(new_source.get(field), str) or not new_source[field]:
            return False
        if old_source.get(field) != new_source[field]:
            return False
    subscription = new_source.get("subscription_id")
    if subscription != old_source.get("subscription_id"):
        return False
    if subscription is not None and (
        not isinstance(subscription, str) or not re.fullmatch(r"[a-f0-9]{16}", subscription)
    ):
        return False
    records = (previous, old_source, current, new_source)
    if any("organization_id" in record or "created_by" in record for record in records):
        owners = [owner_from_record(record) for record in records]
        return owners[0] is not None and all(owner == owners[0] for owner in owners)
    return True
