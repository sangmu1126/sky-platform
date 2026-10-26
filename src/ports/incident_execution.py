"""Registered Sky operation barrier; does not fence arbitrary AWS principals."""

from typing import Protocol

from domain.access import Principal


class IncidentExecutionControl(Protocol):
    def fence(
        self,
        principal: Principal,
        job_id: str,
        *,
        incident_id: str,
        expected_boundary: str,
        expected_revision: int,
    ) -> dict: ...

    def inspect(
        self,
        principal: Principal,
        job_id: str,
        *,
        incident_id: str,
        expected_boundary: str,
        expected_revision: int,
    ) -> dict: ...
