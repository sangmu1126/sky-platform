"""Immutable, bounded observations from operator-registered inventory readers.

These objects are internal port results, not proof supplied by an HTTP client.
Resource ownership is verified outside SQL; SQL cannot establish an AWS account
or a VM's ownership. Neither observation authorizes a migration.
"""

import re
from dataclasses import dataclass
from datetime import datetime

from domain.database_migration import DatabasePlacement, _reference


def aware_time(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Timezone-aware inventory observation required")


@dataclass(frozen=True)
class DatabaseResourceEvidence:
    placement: DatabasePlacement
    evidence_ref: str
    observed_at: datetime
    server_hostname: str
    server_port: int

    def __post_init__(self) -> None:
        if not isinstance(self.placement, DatabasePlacement) or self.placement.role == "sky_state":
            raise ValueError("Verified workload placement required")
        _reference(self.evidence_ref, "resource evidence")
        aware_time(self.observed_at)
        if not isinstance(self.server_hostname, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}", self.server_hostname
        ):
            raise ValueError("Pinned database server hostname required")
        if type(self.server_port) is not int or not 1 <= self.server_port <= 65535:
            raise ValueError("Pinned database server port required")


@dataclass(frozen=True)
class DatabaseInventory:
    plan_id: str
    placement: DatabasePlacement
    resource: DatabaseResourceEvidence
    observed_at: datetime
    server_version_num: int
    extensions: tuple[tuple[str, str], ...]
    table_count: int
    schema_status: str
    schema_sha256: str | None
    encoding: str
    collation: str
    ctype: str

    def __post_init__(self) -> None:
        if not isinstance(self.plan_id, str) or not re.fullmatch(r"DBM-[a-f0-9]{64}", self.plan_id):
            raise ValueError("Inventory must bind an exact migration plan")
        if (
            not isinstance(self.placement, DatabasePlacement)
            or not isinstance(self.resource, DatabaseResourceEvidence)
            or self.resource.placement != self.placement
        ):
            raise ValueError("Inventory resource ownership differs from placement")
        aware_time(self.observed_at)
        if type(self.server_version_num) is not int or not 100000 <= self.server_version_num < 1000000:
            raise ValueError("Explicit PostgreSQL 10+ server version required")
        if type(self.table_count) is not int or not 0 <= self.table_count < 2**31:
            raise ValueError("Invalid inventory table count")
        if self.schema_status not in {"supported", "unsupported"}:
            raise ValueError("Invalid inspected schema status")
        if self.schema_status == "supported":
            if not isinstance(self.schema_sha256, str) or not re.fullmatch(
                r"[a-f0-9]{64}", self.schema_sha256
            ):
                raise ValueError("Supported schema requires a fingerprint")
        elif self.schema_sha256 is not None:
            raise ValueError("Unsupported schema cannot claim a supported fingerprint")
        if not isinstance(self.extensions, tuple) or len(self.extensions) > 32:
            raise ValueError("Bounded immutable extension inventory required")
        for item in self.extensions:
            if (
                not isinstance(item, tuple)
                or len(item) != 2
                or any(
                    not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}", value)
                    for value in item
                )
            ):
                raise ValueError("Invalid extension inventory")
        if tuple(sorted(self.extensions)) != self.extensions or len({e[0] for e in self.extensions}) != len(
            self.extensions
        ):
            raise ValueError("Canonical unique extension inventory required")
        if any(
            not isinstance(value, str) or not 1 <= len(value) <= 256
            for value in (self.encoding, self.collation, self.ctype)
        ):
            raise ValueError("Explicit database encoding and locale required")


class DatabaseInventoryUnavailable(Exception):
    """Sanitized collection failure; never include driver or credential details."""
