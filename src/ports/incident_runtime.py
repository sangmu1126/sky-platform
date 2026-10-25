"""Native observation of the recorded workload; never grants recovery authority."""

from collections.abc import Callable
from typing import Protocol


class IncidentRuntimeInspection(Protocol):
    def inspect(self, result: dict, *, guard: Callable[[], object]) -> dict: ...
