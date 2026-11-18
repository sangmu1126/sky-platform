"""Bind reviewed executions to server-installed resource and effect providers."""

import re
from dataclasses import dataclass

from application.environment_admission import RegisteredEnvironmentExecution

_RESOURCE_REF = re.compile(r"EVR-[a-f0-9]{64}\Z")
_EFFECT_REF = re.compile(r"EEF-[a-f0-9]{64}\Z")


@dataclass(frozen=True)
class RegisteredEnvironmentExecutionComposition:
    execution: RegisteredEnvironmentExecution
    resource_verifier_ref: str
    resource_verifier: object
    effect_ref: str
    effect: object

    def __post_init__(self):
        if not isinstance(self.execution, RegisteredEnvironmentExecution):
            raise TypeError("Registered environment execution required")
        if (
            not isinstance(self.resource_verifier_ref, str)
            or not _RESOURCE_REF.fullmatch(self.resource_verifier_ref)
            or not isinstance(self.effect_ref, str)
            or not _EFFECT_REF.fullmatch(self.effect_ref)
        ):
            raise ValueError("Pinned environment resource and effect references required")
        if not callable(getattr(self.resource_verifier, "verify", None)) or not callable(self.effect):
            raise TypeError("Registered environment resource verifier and effect required")


class RegisteredEnvironmentResourceRouter:
    def __init__(self, compositions):
        self.compositions = _compositions(compositions)

    def verify(self, execution, *, guard):
        selected = self.compositions.get(execution.job.id)
        if selected is None or selected.execution != execution:
            raise ValueError("Environment resource verifier registration changed")
        return selected.resource_verifier.verify(execution, guard=guard)


class RegisteredEnvironmentEffectRouter:
    def __init__(self, compositions):
        self.compositions = _compositions(compositions)

    def __call__(self, execution, *, guard, journal):
        selected = self.compositions.get(execution.job.id)
        if selected is None or selected.execution != execution:
            raise ValueError("Environment effect registration changed")
        return selected.effect(execution, guard=guard, journal=journal)


def _compositions(values):
    if (
        not isinstance(values, tuple)
        or not 1 <= len(values) <= 50
        or not all(isinstance(value, RegisteredEnvironmentExecutionComposition) for value in values)
    ):
        raise ValueError("Bounded registered environment compositions required")
    result = {value.execution.job.id: value for value in values}
    if len(result) != len(values):
        raise ValueError("Duplicate environment execution composition")
    return result
