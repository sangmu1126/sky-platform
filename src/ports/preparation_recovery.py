"""Trusted executor fencing for preparation reconciliation, never browser input."""

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from typing import Protocol

from ports.operations import Operation


@dataclass(frozen=True)
class PreparationRecoveryFence:
    workspace: str
    operation_id: str
    attempt_id: str
    row_version: int
    evidence_ref: str
    check: Callable[[], None] = field(repr=False, compare=False)


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
