"""One workload Secret access fence, not credential erasure or executor exclusion."""

from collections.abc import Callable
from typing import Protocol


class IncidentSecretAccess(Protocol):
    def preflight(self, context: dict, *, guard: Callable[[], object]) -> dict: ...

    def fence(self, context: dict, target: dict, *, guard: Callable[[], object]) -> dict: ...

    def inspect(self, context: dict, target: dict, *, guard: Callable[[], object]) -> dict: ...
