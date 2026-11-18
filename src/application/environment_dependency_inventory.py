"""Bridge registered workload inventory into the G1 preservation obligation."""

from copy import deepcopy
from datetime import datetime

from domain.environment_transition import PreservationObservation, PreservationRequirement
from domain.workload_inventory import RegisteredWorkloadInventory
from engine.workload_inventory import assess_workload_inventory
from ports.environment_transition import PreservationCollectionUnavailable


def dependency_inventory_requirement(registration):
    if not isinstance(registration, RegisteredWorkloadInventory):
        raise TypeError("Registered workload inventory required")
    document = registration.document()
    return PreservationRequirement(
        "dependency_inventory",
        registration.inventory_ref,
        document["inventory_id"][4:],
    )


class RegisteredDependencyInventoryCollector:
    def __init__(
        self,
        registration,
        source_reader,
        target_reader,
        publisher,
        *,
        verifier_ref,
        clock,
    ):
        if not isinstance(registration, RegisteredWorkloadInventory):
            raise TypeError("Registered workload inventory required")
        if not all(
            callable(value)
            for value in (
                getattr(source_reader, "collect", None),
                getattr(target_reader, "collect", None),
                getattr(publisher, "publish", None),
                clock,
            )
        ):
            raise TypeError("Registered readers, publisher and clock required")
        from domain.environment_transition import _ref

        _ref(verifier_ref)
        self.registration = registration
        self.readers = {"source": source_reader, "target": target_reader}
        self.publisher = publisher
        self.verifier_ref = verifier_ref
        self.clock = clock

    def collect(self, scope, requirements):
        expected = dependency_inventory_requirement(self.registration)
        if scope != self.registration.scope or requirements != (expected,):
            raise ValueError("Dependency inventory collection scope differs from registration")
        try:
            snapshots = {
                endpoint: self.readers[endpoint].collect(self.registration, endpoint)
                for endpoint in ("source", "target")
            }
            report = assess_workload_inventory(
                self.registration, snapshots["source"], snapshots["target"], now=self.clock()
            )
            evidence_ref = self.publisher.publish(deepcopy(report))
            if evidence_ref != report["report_id"]:
                raise ValueError("Workload inventory publisher changed report identity")
        except Exception:  # noqa: BLE001 -- provider/publisher diagnostics may contain credentials
            raise PreservationCollectionUnavailable(
                "Registered workload dependency inventory unavailable"
            ) from None
        evaluated = datetime.fromisoformat(report["evaluated_at"])
        expires = datetime.fromisoformat(report["expires_at"])
        if expires <= evaluated:
            raise PreservationCollectionUnavailable("Registered workload dependency inventory expired")
        return tuple(
            PreservationObservation(
                scope,
                expected,
                endpoint,
                evidence_ref,
                self.verifier_ref,
                evaluated,
                expires,
                report["endpoint_status"][endpoint],
            )
            for endpoint in ("source", "target")
        )
