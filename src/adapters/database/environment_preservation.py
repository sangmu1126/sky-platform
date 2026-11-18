"""Narrow bridge from registered SQL preflight to environment review evidence.

This never verifies baseline persistence, whole-environment TLS/security,
replication, backup, recovery, or downtime. It verifies only the two explicitly
versioned supplemental database criteria below, using its own fresh collection.
"""

import hashlib
from dataclasses import asdict
from datetime import datetime, timedelta

from application.database_migration_preflight import DatabaseMigrationPreflight, validate_preflight_report
from domain.database_migration import DatabasePlacement, MigrationSafetyPolicy, validate_workload_ownership
from domain.environment_transition import (
    PreservationObservation,
    PreservationRequirement,
    TransitionScope,
    _ref,
)


def _criterion(capability, description):
    return PreservationRequirement(
        capability, capability + "-v1", hashlib.sha256(description.encode()).hexdigest()
    )


DATABASE_PRESERVATION_CRITERIA = (
    _criterion(
        "database_resource_ownership",
        "Registered SQL reader verified exact app/org/database/resource ownership and pinned endpoint. "
        "Does not establish application-level identity policy or whole-environment access equivalence.",
    ),
    _criterion(
        "database_metadata_compatibility",
        "Both registered SQL inventories passed the bounded metadata preflight: declared same major, "
        "supported schema/extensions, nonempty bounded source and empty target, equal encoding/locale names. "
        "No data copy, collation implementation equivalence, write control or backup is established.",
    ),
)


class DatabasePreservationCollector:
    def __init__(
        self,
        preflight: DatabaseMigrationPreflight,
        source: DatabasePlacement,
        target: DatabasePlacement,
        policy: MigrationSafetyPolicy,
        *,
        scope: TransitionScope,
        verifier_ref: str,
    ):
        if not isinstance(preflight, DatabaseMigrationPreflight):
            raise TypeError("Registered database preflight service required")
        if not isinstance(scope, TransitionScope) or not isinstance(policy, MigrationSafetyPolicy):
            raise TypeError("Typed registered scope and database policy required")
        if not isinstance(source, DatabasePlacement) or not isinstance(target, DatabasePlacement):
            raise TypeError("Typed registered database placements required")
        validate_workload_ownership(source, target)
        if (scope.organization_id, scope.application_id) != (source.organization_id, source.application_id):
            raise ValueError("Database registration ownership differs from transition")
        _ref(verifier_ref)
        self.preflight, self.source, self.target, self.policy = preflight, source, target, policy
        self.scope, self.verifier_ref = scope, verifier_ref

    def collect(self, scope, requirements):
        if scope != self.scope:
            raise ValueError("Database collector scope changed")
        if (
            not isinstance(requirements, tuple)
            or not requirements
            or len(set(requirements)) != len(requirements)
            or any(item not in DATABASE_PRESERVATION_CRITERIA for item in requirements)
        ):
            raise ValueError("Database preflight cannot verify this preservation criterion")
        # Never accept a user-supplied, previously approved or arbitrary report.
        report = validate_preflight_report(
            self.preflight.inspect(
                self.source, self.target, self.policy, source_revision=scope.source_revision
            )
        )
        if (
            report["source"] != asdict(self.source)
            or report["target"] != asdict(self.target)
            or report["source_revision"] != scope.source_revision
            or report["safety_policy"] != asdict(self.policy)
        ):
            raise ValueError("Database preflight registration changed")
        preflight = report["preflight"]
        checks = {item["name"]: item["status"] for item in preflight["checks"]}
        compatible = all(
            checks.get(name) == "verified"
            for name in ("declared_versions", "schema_and_extensions", "database_locale")
        )
        incompatible = any(
            checks.get(name) == "blocked"
            for name in ("declared_versions", "schema_and_extensions", "database_locale")
        )
        results = []
        for endpoint in ("source", "target"):
            inventory = preflight["inventories"].get(endpoint)
            if inventory is None or checks.get(endpoint + "_inventory") != "verified":
                continue
            observed = min(
                datetime.fromisoformat(inventory["observed_at"]),
                datetime.fromisoformat(inventory["resource"]["observed_at"]),
            )
            for criterion in requirements:
                status = "verified"
                if criterion.capability == "database_metadata_compatibility":
                    status = "verified" if compatible else "failed" if incompatible else "unknown"
                results.append(
                    PreservationObservation(
                        scope,
                        criterion,
                        endpoint,
                        preflight["evidence_id"] + "-" + endpoint,
                        self.verifier_ref,
                        observed,
                        observed + timedelta(seconds=preflight["max_age_seconds"]),
                        status,
                    )
                )
        return tuple(results)
