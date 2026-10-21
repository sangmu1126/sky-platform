"""Trusted executor fencing for preparation reconciliation, never browser input."""

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from typing import Protocol

from ports.operations import Operation
from ports.preparation_executor import CreateOnlyPreparationProfile


@dataclass(frozen=True)
class AvailableTargetRecoveryEvidence:
    profile: CreateOnlyPreparationProfile
    stopped_evidence_ref: str
    stopped_at: str
    target_resource_id: str

    def record(self):
        # Constructed by a trusted authority, never from an HTTP request.
        import re
        from datetime import datetime

        if (
            not isinstance(self.profile, CreateOnlyPreparationProfile)
            or not isinstance(self.stopped_evidence_ref, str)
            or not re.fullmatch(r"evidence:ecs-stopped/[a-f0-9]{64}", self.stopped_evidence_ref)
            or not isinstance(self.target_resource_id, str)
            or not re.fullmatch(r"db-[A-Za-z0-9]{16,64}", self.target_resource_id)
        ):
            raise ValueError("Scoped available-target recovery evidence required")
        if not isinstance(self.stopped_at, str) or datetime.fromisoformat(self.stopped_at).tzinfo is None:
            raise ValueError("Verified executor stop time required")
        return {
            "policy_id": "stopped-create-only-existing-protected-target-v1",
            "execution_profile": self.profile.record(),
            "stopped_evidence_ref": self.stopped_evidence_ref,
            "stopped_at": self.stopped_at,
            "target_resource_id": self.target_resource_id,
            "requests_cancelled": False,
        }


@dataclass(frozen=True)
class PreparationRecoveryFence:
    workspace: str
    operation_id: str
    attempt_id: str
    row_version: int
    evidence_ref: str
    check: Callable[[], None] = field(repr=False, compare=False)
    evidence: AvailableTargetRecoveryEvidence | None = None


class PreparationRecoveryAuthority(Protocol):
    def hold(self, operation: Operation) -> AbstractContextManager[PreparationRecoveryFence]:
        """Establish and hold exclusion against the original executor's effects.

        Implementations must verify that the original executor cannot send late
        requests and that already sent provider requests cannot invalidate the
        observation. Lease expiry, an absent resource or a user's boolean is not
        such proof. check() must raise when this guarantee is lost or expires.
        This port has no default implementation and is not an AWS cancellation API.
        """
        ...
