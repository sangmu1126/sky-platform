"""Provider-neutral review plans. No returned plan is executable or approved.

Route availability is deliberately separate from unverified safety obligations.
Existing executor availability is not evidence of version/schema compatibility,
single-writer control, timing guarantees, or recovery for a particular app.
"""

import hashlib
import json
import re
from dataclasses import asdict

from domain.database_migration import (
    DatabasePlacement,
    MigrationSafetyPolicy,
    validate_workload_ownership,
)

_OBLIGATIONS = (
    "source_target_ownership",
    "supported_schema_and_extensions",
    "source_inventory",
    "target_security_equivalence",
    "target_capacity_and_recovery",
    "cost_and_approval",
    "all_writers_controlled",
    "initial_copy_integrity",
    "final_sync_integrity",
    "single_writer_cutover",
    "stable_endpoint_ownership",
    "application_read_write_probe",
    "write_pause_budget_measured",
    "recovery_rehearsal",
    "source_retention",
)


def plan_database_migration(
    source: DatabasePlacement,
    target: DatabasePlacement,
    policy: MigrationSafetyPolicy,
    *,
    source_revision: str,
) -> dict:
    if not isinstance(source, DatabasePlacement) or not isinstance(target, DatabasePlacement):
        raise TypeError("Migration requires typed database placements")
    if not isinstance(policy, MigrationSafetyPolicy):
        raise TypeError("Migration requires an explicit safety policy")
    validate_workload_ownership(source, target)
    if (source.location, source.instance_id) == (target.location, target.instance_id):
        raise ValueError("Migration requires a different database instance")
    if not isinstance(source_revision, str) or not re.fullmatch(r"[a-f0-9]{64}", source_revision):
        raise ValueError("Migration requires a source revision digest")

    payload = {
        "schema_version": 1,
        "source": asdict(source),
        "target": asdict(target),
        "source_revision": source_revision,
        "safety_policy": asdict(policy),
    }
    identity = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    blockers = []
    legacy_route = (
        source.location.provider == "aws"
        and source.location == target.location
        and source.role == "shared_workload"
        and target.role == "dedicated_workload"
    )
    if not legacy_route:
        blockers.append("route_not_implemented")
    if policy.method != "write_freeze":
        blockers.append("continuous_sync_not_implemented")
    if policy.method == "write_freeze" and policy.write_pause_budget_seconds == 0:
        blockers.append("write_freeze_requires_pause_budget")
    if policy.recovery_point_objective_seconds != 0:
        blockers.append("lossy_recovery_policy_not_supported")
    if source.postgres_major != target.postgres_major:
        blockers.append("postgres_major_change_not_supported")

    return {
        **payload,
        "plan_id": "DBM-" + hashlib.sha256(identity.encode()).hexdigest(),
        "route_status": "existing_executor" if legacy_route else "unsupported_by_sky",
        "blockers": blockers,
        "required_gates": [{"name": name, "status": "unverified"} for name in _OBLIGATIONS],
        "approval_required": True,
        "ready_to_cutover": False,
        "execution_status": "blocked",
        "source_retirement_status": "blocked_until_verified_recovery_window_closes",
    }
