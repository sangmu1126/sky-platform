"""Credential preparation while access remains restricted; never resumes a runtime."""

from collections.abc import Callable
from typing import Protocol

from domain.database import DatabaseBinding


class IncidentCredentialPreparation(Protocol):
    binding: DatabaseBinding
    resource_id: str
    principal_arn: str

    def prepare(self, operation_id: str, *, guard: Callable[[], object]) -> dict: ...
