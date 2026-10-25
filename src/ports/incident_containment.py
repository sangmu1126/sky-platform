"""Contain the registered service's automatic scaling; never restore access."""

from collections.abc import Callable
from typing import Protocol


class IncidentRuntimeContainment(Protocol):
    def preflight(self, result: dict, *, guard: Callable[[], object]) -> dict: ...

    def request(self, result: dict, target: dict, *, guard: Callable[[], object]) -> dict: ...

    def inspect(self, result: dict, target: dict, *, guard: Callable[[], object]) -> dict: ...
