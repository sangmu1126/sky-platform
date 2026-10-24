"""Trusted registered restriction; callers cannot request login restoration."""

from collections.abc import Callable
from typing import Protocol

from domain.database import DatabaseBinding


class DatabaseRestriction(Protocol):
    binding: DatabaseBinding

    def restrict(self, *, guard: Callable[[], object]) -> dict: ...

    def inspect(self, *, guard: Callable[[], object]) -> dict: ...
