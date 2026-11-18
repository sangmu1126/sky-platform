"""Operator-owned collection and registration ports; never supplied by clients."""

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from domain.access import Principal
from domain.environment_transition import PreservationObservation, PreservationRequirement, TransitionScope


class PreservationCollectionUnavailable(Exception):
    """Sanitized collection failure. Incomplete evidence must remain unverified."""


@dataclass(frozen=True)
class EnvironmentPreservationReview:
    id: str
    registration_id: str
    report_id: str
    expires_at: datetime
    approved_by: str | None
    approval_scope: str = "environment_preservation_review_only"
    execution_authorized: bool = False


class PreservationCollector(Protocol):
    def collect(
        self, scope: TransitionScope, requirements: tuple[PreservationRequirement, ...]
    ) -> tuple[PreservationObservation, ...]:
        """Read registered resources with bounded I/O; no production mutations."""
        ...


class TransitionAuthorizer(Protocol):
    def authorize(self, principal: Principal, application_id: str) -> None:
        """Check existing app ownership and principal permissions, or raise.

        Admission at HTTP enqueue time is not sufficient. Do not create or adopt
        an application as part of this check. PostgresMigrationReviews supplies
        this interface for the existing database application owner ledger. It
        does not reload membership: a separate current-principal resolver must
        do that at every collection boundary.
        """
        ...
