"""Bind live database and route ownership evidence to one reviewed execution."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict
from datetime import datetime

from adapters.database.environment_execution_runtime import RegisteredEnvironmentTransferRuntime
from adapters.database.environment_transfer import RegisteredTransferEndpoint
from adapters.onprem.environment_router import EnvironmentNginxRouter, RegisteredEnvironmentRouter
from application.environment_admission import RegisteredEnvironmentExecution
from application.environment_execution_effect import RegisteredEnvironmentResourceCheck
from domain.database_inventory import DatabaseResourceEvidence

_RUNTIME_REF = re.compile(r"ETR-[a-f0-9]{64}\Z")


def _reference(profile, value):
    raw = json.dumps(
        {"schema_version": 1, "profile": profile, **value},
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return "ERC-" + hashlib.sha256(raw).hexdigest()


def _endpoint_name(execution, endpoint):
    placement = endpoint.inventory.resource
    if placement == execution.job.transfer.source:
        return "source"
    if placement == execution.job.transfer.target:
        return "target"
    raise ValueError("Database resource check differs from reviewed transfer")


class RegisteredDatabaseExecutionResourceCheck:
    """Adapt an existing read-only ownership verifier to an ERC receipt."""

    def __init__(self, execution, endpoint, verifier, *, clock):
        if not isinstance(execution, RegisteredEnvironmentExecution):
            raise TypeError("Registered environment execution required")
        if not isinstance(endpoint, RegisteredTransferEndpoint):
            raise TypeError("Registered transfer endpoint required")
        if not callable(getattr(verifier, "verify", None)) or not callable(clock):
            raise TypeError("Read-only database verifier and clock required")
        side = _endpoint_name(execution, endpoint)
        self.execution, self.endpoint, self.verifier = execution, endpoint, verifier
        self.clock, self.side = clock, side
        self.reference = self._current_reference()

    def _current_reference(self):
        try:
            inventory = self.endpoint.inventory
            return _reference(
                "registered_database_execution_resource_v1",
                {
                    "execution_revision": self.execution.revision,
                    "endpoint": _endpoint_name(self.execution, self.endpoint),
                    "placement": asdict(inventory.resource),
                    "hostname": inventory.hostname,
                    "port": inventory.port,
                    "login_role": inventory.login_role,
                    "ca_sha256": inventory.ca_sha256,
                    "connect_port": self.endpoint.connect_port,
                    "connect_hostaddr": self.endpoint.connect_hostaddr,
                },
            )
        except (AttributeError, TypeError, ValueError):
            return None

    def collect(self, execution, *, guard):
        if execution != self.execution or not callable(guard) or self.reference != self._current_reference():
            raise ValueError("Exact guarded database resource execution required")
        inventory = self.endpoint.inventory
        guard()
        proof = self.verifier.verify(inventory.resource)
        now = self.clock()
        if (
            not isinstance(proof, DatabaseResourceEvidence)
            or proof.placement != inventory.resource
            or (proof.server_hostname, proof.server_port) != (inventory.hostname, inventory.port)
            or not isinstance(now, datetime)
            or now.tzinfo is None
            or not 0 <= (now - proof.observed_at).total_seconds() < 60
        ):
            raise ValueError("Current registered database ownership evidence required")
        guard()
        return {"check_ref": self.reference, "evidence_ref": proof.evidence_ref}

    def check(self):
        return RegisteredEnvironmentResourceCheck(self.reference, self.collect)


class RegisteredRouteExecutionResourceCheck:
    """Require the registered source route and both pinned runtimes before copy."""

    def __init__(self, execution, registration, router_factory):
        if not isinstance(execution, RegisteredEnvironmentExecution):
            raise TypeError("Registered environment execution required")
        if (
            not isinstance(registration, RegisteredEnvironmentRouter)
            or registration.transfer != execution.job.transfer
        ):
            raise ValueError("Registered route differs from reviewed transfer")
        if not callable(router_factory):
            raise TypeError("Guard-bound environment router factory required")
        self.execution, self.registration = execution, registration
        self.router_factory = router_factory
        self.reference = self._current_reference()

    def _current_reference(self):
        try:
            return _reference(
                "registered_route_execution_resource_v1",
                {
                    "execution_revision": self.execution.revision,
                    "router": asdict(self.registration),
                    "required_binding": asdict(self.execution.job.transfer.source),
                },
            )
        except (AttributeError, TypeError, ValueError):
            return None

    def collect(self, execution, *, guard):
        if execution != self.execution or not callable(guard) or self.reference != self._current_reference():
            raise ValueError("Exact guarded route resource execution required")
        guard()
        router = self.router_factory(execution, guard=guard)
        if (
            not isinstance(router, EnvironmentNginxRouter)
            or router.registration != self.registration
            or router.guard is not guard
        ):
            raise ValueError("Guard-bound registered environment router required")
        binding = asdict(execution.job.transfer.source)
        result = router.probe(binding)
        if result != {"binding": binding, "verified_scope": "routed_https_database_read"}:
            raise ValueError("Current registered source route evidence required")
        guard()
        evidence = (
            "ROUTE-"
            + hashlib.sha256(
                json.dumps(
                    {"check_ref": self.reference, "result": result},
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode()
            ).hexdigest()
        )
        return {"check_ref": self.reference, "evidence_ref": evidence}

    def check(self):
        return RegisteredEnvironmentResourceCheck(self.reference, self.collect)


class RegisteredRuntimeExecutionResourceCheck:
    """Open pinned materials for read-only DB, runtime, and route verification."""

    def __init__(self, execution, runtime_ref, runtime):
        if not isinstance(execution, RegisteredEnvironmentExecution):
            raise TypeError("Registered environment execution required")
        if (
            not isinstance(runtime_ref, str)
            or not _RUNTIME_REF.fullmatch(runtime_ref)
            or not isinstance(runtime, RegisteredEnvironmentTransferRuntime)
            or runtime.reference != runtime_ref
            or runtime.execution != execution
        ):
            raise ValueError("Exact registered environment runtime required")
        self.execution, self.runtime_ref, self.runtime = execution, runtime_ref, runtime
        self.reference = self._current_reference()

    def _current_reference(self):
        try:
            return _reference(
                "registered_runtime_execution_resource_v1",
                {
                    "execution_revision": self.execution.revision,
                    "runtime_ref": self.runtime_ref,
                    "required_binding": asdict(self.execution.job.transfer.source),
                    "checks": [
                        "database_registration",
                        "source_runtime",
                        "target_runtime",
                        "source_route",
                    ],
                },
            )
        except (AttributeError, TypeError, ValueError):
            return None

    def collect(self, execution, *, guard):
        if (
            execution != self.execution
            or not callable(guard)
            or self.reference != self._current_reference()
            or not isinstance(self.runtime, RegisteredEnvironmentTransferRuntime)
            or self.runtime.reference != self.runtime_ref
            or self.runtime.execution != execution
        ):
            raise ValueError("Exact guarded runtime resource execution required")

        def no_effect_journal(_value):
            raise RuntimeError("Resource verification cannot record external-effect intent")

        guard()
        with self.runtime(execution, guard=guard, journal=no_effect_journal) as (transport, flow):
            verification = transport.verify_registration(execution.job.transfer, guard=guard)
            plan_id = execution.job.transfer.document()["plan_id"]
            if verification != {
                "plan_id": plan_id,
                "registration_verified": True,
                "mutation": False,
            }:
                raise ValueError("Current registered database verification required")
            binding = asdict(execution.job.transfer.source)
            route = flow.traffic.router.probe(binding)
            if route != {"binding": binding, "verified_scope": "routed_https_database_read"}:
                raise ValueError("Current registered source route verification required")
            guard()
        evidence = hashlib.sha256(
            json.dumps(
                {
                    "check_ref": self.reference,
                    "execution_revision": execution.revision,
                    "runtime_ref": self.runtime_ref,
                    "database": verification,
                    "route": route,
                },
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode()
        ).hexdigest()
        return {"check_ref": self.reference, "evidence_ref": "ENVRT-" + evidence}

    def check(self):
        return RegisteredEnvironmentResourceCheck(self.reference, self.collect)


def registered_environment_transfer_resource_checks(
    execution,
    *,
    source_endpoint,
    source_verifier,
    target_endpoint,
    target_verifier,
    router_registration,
    router_factory,
    clock,
):
    """Return the canonical three checks consumed by the fixed EVR aggregator."""
    values = (
        RegisteredDatabaseExecutionResourceCheck(
            execution, source_endpoint, source_verifier, clock=clock
        ).check(),
        RegisteredDatabaseExecutionResourceCheck(
            execution, target_endpoint, target_verifier, clock=clock
        ).check(),
        RegisteredRouteExecutionResourceCheck(execution, router_registration, router_factory).check(),
    )
    return tuple(sorted(values, key=lambda value: value.reference))
