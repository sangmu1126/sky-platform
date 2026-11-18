"""Resolve pinned secret versions into one guarded environment transfer runtime."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass

from adapters.database.environment_control import EnvironmentApplicationControl
from adapters.database.environment_fence import PostgresEnvironmentWriteFence
from adapters.database.environment_traffic import EnvironmentBlueGreenTraffic
from adapters.database.environment_transfer import PostgresEnvironmentTransfer
from adapters.onprem.environment_router import EnvironmentNginxRouter
from application.environment_admission import RegisteredEnvironmentExecution
from application.environment_cutover import EnvironmentDatabaseCutover
from domain.environment_transition import _ref

_COMPOSITION_REF = re.compile(r"RTC-[a-f0-9]{64}\Z")
_RESOLVER_REF = re.compile(r"ESR-[a-f0-9]{64}\Z")
_PURPOSES = (
    "router_transport",
    "entrypoint_probe",
    "source_control",
    "source_database",
    "target_control",
    "target_database",
)


@dataclass(frozen=True)
class RegisteredEnvironmentRuntimeSecret:
    purpose: str
    secret_ref: str
    version_ref: str

    def __post_init__(self):
        if self.purpose not in _PURPOSES:
            raise ValueError("Bounded environment runtime secret purpose required")
        _ref(self.secret_ref)
        _ref(self.version_ref)


@dataclass(frozen=True)
class RegisteredEnvironmentTransferRuntimeRegistration:
    execution_revision: str
    secret_resolver_ref: str
    composition_ref: str
    secrets: tuple[RegisteredEnvironmentRuntimeSecret, ...]

    def __post_init__(self):
        if (
            not isinstance(self.execution_revision, str)
            or not re.fullmatch(r"[a-f0-9]{64}", self.execution_revision)
            or not isinstance(self.secret_resolver_ref, str)
            or not _RESOLVER_REF.fullmatch(self.secret_resolver_ref)
            or not isinstance(self.composition_ref, str)
            or not _COMPOSITION_REF.fullmatch(self.composition_ref)
            or not isinstance(self.secrets, tuple)
            or not all(isinstance(value, RegisteredEnvironmentRuntimeSecret) for value in self.secrets)
            or tuple(value.purpose for value in self.secrets) != _PURPOSES
            or len({value.secret_ref for value in self.secrets}) != len(self.secrets)
            or len({(value.secret_ref, value.version_ref) for value in self.secrets}) != len(self.secrets)
        ):
            raise ValueError("Canonical environment transfer runtime registration required")

    def document(self):
        value = {
            "schema_version": 1,
            "profile": "registered_environment_transfer_runtime_v1",
            "execution_revision": self.execution_revision,
            "secret_resolver_ref": self.secret_resolver_ref,
            "composition_ref": self.composition_ref,
            "secrets": [asdict(value) for value in self.secrets],
        }
        digest = hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        return {**value, "runtime_ref": "ETR-" + digest}


class RegisteredEnvironmentTransferRuntime:
    """Open exact secret versions only for the lifetime of one guarded effect."""

    def __init__(self, execution, registration, resolver, composer):
        if not isinstance(execution, RegisteredEnvironmentExecution):
            raise TypeError("Registered environment execution required")
        if (
            not isinstance(registration, RegisteredEnvironmentTransferRuntimeRegistration)
            or registration.execution_revision != execution.revision
        ):
            raise ValueError("Runtime registration differs from reviewed execution")
        if not callable(getattr(resolver, "open", None)) or not callable(composer):
            raise TypeError("Registered secret resolver and runtime composer required")
        if (
            getattr(resolver, "reference", None) != registration.secret_resolver_ref
            or getattr(composer, "reference", None) != registration.composition_ref
        ):
            raise ValueError("Runtime resolver or composer differs from registration")
        self.execution, self.registration = execution, registration
        self.resolver, self.composer = resolver, composer
        self.reference = registration.document()["runtime_ref"]

    @staticmethod
    def _validate_runtime(execution, transport, flow, *, guard, journal):
        transfer = execution.job.transfer
        if (
            not isinstance(transport, PostgresEnvironmentTransfer)
            or transport.transfer != transfer
            or not isinstance(flow, EnvironmentDatabaseCutover)
            or flow.transfer != transfer
            or flow._external_guard is not guard
            or flow.journal is not journal
            or getattr(flow.sync, "transport", None) is not transport
            or not isinstance(flow.source, PostgresEnvironmentWriteFence)
            or not isinstance(flow.target, PostgresEnvironmentWriteFence)
            or flow.source.transport is not transport
            or flow.target.transport is not transport
            or not isinstance(flow.traffic, EnvironmentBlueGreenTraffic)
            or flow.traffic.guard is not guard
            or not isinstance(flow.traffic.router, EnvironmentNginxRouter)
            or flow.traffic.router.registration.transfer != transfer
            or flow.traffic.router.guard is not guard
            or len(flow.traffic.controllers) != 2
            or not all(
                isinstance(value, EnvironmentApplicationControl)
                and value.transfer == transfer
                and value.guard is guard
                for value in flow.traffic.controllers
            )
        ):
            raise ValueError("Exact guarded environment transfer runtime required")
        return transport, flow

    @contextmanager
    def __call__(self, execution, *, guard, journal):
        if execution != self.execution or not callable(guard) or not callable(journal):
            raise ValueError("Exact guarded environment transfer runtime execution required")
        stack = ExitStack()
        materials = {}
        try:
            try:
                for secret in self.registration.secrets:
                    guard()
                    context = self.resolver.open(
                        secret.secret_ref,
                        secret.version_ref,
                        execution=execution,
                        purpose=secret.purpose,
                        guard=guard,
                    )
                    material = stack.enter_context(context)
                    if material is None:
                        raise ValueError("Resolved environment runtime secret is unavailable")
                    materials[secret.purpose] = material
                    guard()
                runtime = self.composer(execution, dict(materials), guard=guard, journal=journal)
                if not isinstance(runtime, tuple) or len(runtime) != 2:
                    raise ValueError("Environment runtime composer returned an invalid result")
                transport, flow = self._validate_runtime(execution, *runtime, guard=guard, journal=journal)
                guard()
            except Exception:  # noqa: BLE001 -- resolver diagnostics and secret metadata stay private
                raise OSError("Registered environment transfer runtime unavailable") from None
            yield transport, flow
        finally:
            original_error = sys.exc_info()[1]
            materials.clear()
            try:
                stack.close()
            except Exception:  # noqa: BLE001 -- never replace the external-effect outcome
                message = "Registered environment runtime secret cleanup failed"
                if original_error is not None:
                    original_error.add_note(message)
                else:
                    raise OSError(message) from None
