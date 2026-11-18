"""Read-only observations obtained by trusted, operator-owned registrations."""

from typing import Protocol

from domain.database_inventory import DatabaseInventory, DatabaseResourceEvidence
from domain.database_migration import DatabasePlacement


class DatabaseResourceVerifier(Protocol):
    def verify(self, placement: DatabasePlacement) -> DatabaseResourceEvidence:
        """Inspect actual provider/VM identity and ownership or raise.

        Match exact organization, app, resource and owner registration. Return
        the actual registered host/port only after verification. User-submitted
        flags and a successful SQL connection do not constitute this proof.
        """
        ...


class DatabaseInventoryReader(Protocol):
    def inspect(self, placement: DatabasePlacement, *, plan_id: str) -> DatabaseInventory:
        """Collect bounded metadata with a pinned, certificate-verified connection.

        No DDL, user row reads, writes, locks for copying, or routing changes.
        Raise DatabaseInventoryUnavailable for sanitized collection failures.
        """
        ...
