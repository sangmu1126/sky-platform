"""Database placement and migration safety contracts, without execution authority.

Registered infrastructure references identify resources; they are not connection
strings or credentials. Describing a route does not authorize or implement it.
Legacy DatabaseBinding remains unchanged for persisted plans and receipts.
"""

import re
from dataclasses import dataclass

from domain.database import DatabaseBinding

_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
_BACKENDS = {"aws": "rds_postgresql", "onprem": "vm_postgresql", "gcp": "cloud_sql_postgresql"}
_ROLES = {"shared_workload", "dedicated_workload", "existing_workload", "sky_state"}


def _reference(value: str, field: str) -> None:
    if not isinstance(value, str) or not _REF.fullmatch(value):
        raise ValueError(f"Invalid migration {field}")


@dataclass(frozen=True)
class DatabaseLocation:
    provider: str
    backend: str
    authority_ref: str
    location: str

    def __post_init__(self) -> None:
        if not isinstance(self.provider, str) or _BACKENDS.get(self.provider) != self.backend:
            raise ValueError("Unknown database provider/backend combination")
        _reference(self.authority_ref, "authority reference")
        _reference(self.location, "location")
        if self.provider == "aws" and not re.fullmatch(r"[0-9]{12}", self.authority_ref):
            raise ValueError("AWS database location requires an account ID")


@dataclass(frozen=True)
class DatabasePlacement:
    organization_id: str
    application_id: str
    role: str
    location: DatabaseLocation
    instance_id: str
    database_name: str
    owner_ref: str
    postgres_major: int

    def __post_init__(self) -> None:
        for field in ("organization_id", "application_id", "instance_id", "database_name", "owner_ref"):
            _reference(getattr(self, field), field)
        if not isinstance(self.role, str) or self.role not in _ROLES:
            raise ValueError("Invalid database placement role")
        if not isinstance(self.location, DatabaseLocation):
            raise TypeError("Database placement requires a typed location")
        if type(self.postgres_major) is not int or self.postgres_major < 1:
            raise ValueError("Explicit PostgreSQL major version required")


@dataclass(frozen=True)
class MigrationSafetyPolicy:
    write_pause_budget_seconds: int
    recovery_time_objective_seconds: int
    source_retention_seconds: int
    recovery_point_objective_seconds: int = 0
    method: str = "write_freeze"

    def __post_init__(self) -> None:
        for field in (
            "write_pause_budget_seconds",
            "recovery_time_objective_seconds",
            "source_retention_seconds",
            "recovery_point_objective_seconds",
        ):
            value = getattr(self, field)
            if type(value) is not int or value < 0:
                raise ValueError(f"Invalid migration safety policy {field}")
        if self.recovery_time_objective_seconds == 0:
            raise ValueError("Positive recovery time objective required")
        if self.source_retention_seconds < self.recovery_time_objective_seconds:
            raise ValueError("Source retention must cover the recovery time objective")
        if not isinstance(self.method, str) or self.method not in {"write_freeze", "cdc"}:
            raise ValueError("Unknown migration method")


def validate_workload_ownership(
    source: DatabaseBinding | DatabasePlacement,
    target: DatabaseBinding | DatabasePlacement,
) -> None:
    if not all(isinstance(item, (DatabaseBinding, DatabasePlacement)) for item in (source, target)):
        raise TypeError("Typed workload database endpoints required")
    if source.role == "sky_state" or target.role == "sky_state":
        raise ValueError("Control-plane database migration is excluded")
    if (source.organization_id, source.application_id) != (target.organization_id, target.application_id):
        raise ValueError("Migration cannot cross organization or application ownership")


def validate_legacy_promotion_route(source: DatabaseBinding, target: DatabaseBinding) -> None:
    """Preserve the existing registered executor's limits, including VM fixtures.

    A legacy binding does not identify its provider. In particular, VM bindings
    must never be silently relabelled as AWS RDS based on their account field.
    """
    if not isinstance(source, DatabaseBinding) or not isinstance(target, DatabaseBinding):
        raise TypeError("Database promotion requires typed source and target bindings")
    if source.role != "shared_workload" or target.role != "dedicated_workload":
        raise ValueError("Only workload shared-to-dedicated promotion can be planned")
    validate_workload_ownership(source, target)
    if (source.account_id, source.region) != (target.account_id, target.region):
        raise ValueError("Cross-account or cross-region migration is not implemented")
    if source.instance_id == target.instance_id:
        raise ValueError("Dedicated RDS must be a different instance")
