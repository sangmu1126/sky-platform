"""Trusted workload dependency inventory ports."""

from typing import Protocol

from domain.workload_inventory import RegisteredWorkloadInventory, WorkloadInventorySnapshot


class WorkloadInventoryUnavailable(Exception):
    """Sanitized collector failure; raw provider/runtime diagnostics stay private."""


class WorkloadInventoryReader(Protocol):
    def collect(self, registration: RegisteredWorkloadInventory, endpoint: str) -> WorkloadInventorySnapshot:
        """Inspect a fixed registered endpoint without mutation."""


class WorkloadInventoryPublisher(Protocol):
    def publish(self, report: dict) -> str:
        """Persist a validated report and return its exact report ID."""
