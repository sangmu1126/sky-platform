"""Explicit bounded PostgreSQL transport registration, separate from DBM review.

An internal registration is not a public approval token. The workflow must
authorize and journal the exact operation before invoking the transport. This
contract does not widen the legacy same-account DBP promotion interface.
"""

import hashlib
import json
from dataclasses import asdict, dataclass

from domain.database_migration import (
    DatabasePlacement,
    MigrationSafetyPolicy,
    _reference,
    validate_workload_ownership,
)


@dataclass(frozen=True)
class RegisteredDatabaseTransfer:
    registration_ref: str
    source: DatabasePlacement
    target: DatabasePlacement
    source_revision: str
    policy: MigrationSafetyPolicy

    def __post_init__(self):
        _reference(self.registration_ref, "transfer registration")
        if not isinstance(self.source, DatabasePlacement) or not isinstance(self.target, DatabasePlacement):
            raise TypeError("Typed registered database placements required")
        validate_workload_ownership(self.source, self.target)
        if {self.source.location.provider, self.target.location.provider} != {"aws", "onprem"}:
            raise ValueError("Registered transport supports only AWS and Linux VM PostgreSQL")
        if any(
            placement.role not in {"existing_workload", "shared_workload", "dedicated_workload"}
            or placement.database_name.startswith("sky_pool_")
            for placement in (self.source, self.target)
        ):
            raise ValueError("Control and pool administration databases cannot be transferred")
        if self.source.postgres_major != self.target.postgres_major:
            raise ValueError("Database major version changes are not supported")
        if (
            not isinstance(self.source_revision, str)
            or len(self.source_revision) != 64
            or any(c not in "0123456789abcdef" for c in self.source_revision)
        ):
            raise ValueError("Exact source revision digest required")
        if not isinstance(self.policy, MigrationSafetyPolicy) or (
            self.policy.method != "write_freeze"
            or self.policy.write_pause_budget_seconds <= 0
            or self.policy.recovery_point_objective_seconds != 0
        ):
            raise ValueError("Explicit positive write-pause budget and zero-loss policy required")

    def document(self) -> dict:
        payload = {"schema_version": 1, "profile": "registered_postgres_write_pause_v1", **asdict(self)}
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return {**payload, "plan_id": "DBT-" + digest}
