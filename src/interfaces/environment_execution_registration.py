"""Operator manifest for server-installed reviewed environment compositions."""

import hashlib
import json
import re
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path

from application.environment_execution_composition import (
    RegisteredEnvironmentExecutionComposition,
)

ENTRY_POINT_GROUP = "sky.environment_execution.v1"
_REF = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,127}\Z")
_PROVIDER = re.compile(r"[a-z][a-z0-9-]{2,63}\Z")
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_RESOURCE_REF = re.compile(r"EVR-[a-f0-9]{64}\Z")
_EFFECT_REF = re.compile(r"EEF-[a-f0-9]{64}\Z")


@dataclass(frozen=True)
class EnvironmentExecutionPin:
    registration_id: str
    execution_revision: str
    application_id: str
    resource_verifier_ref: str
    effect_ref: str

    def __post_init__(self):
        if (
            not all(
                isinstance(value, str) and _REF.fullmatch(value)
                for value in (
                    self.registration_id,
                    self.application_id,
                )
            )
            or not isinstance(self.execution_revision, str)
            or not _DIGEST.fullmatch(self.execution_revision)
            or not isinstance(self.resource_verifier_ref, str)
            or not _RESOURCE_REF.fullmatch(self.resource_verifier_ref)
            or not isinstance(self.effect_ref, str)
            or not _EFFECT_REF.fullmatch(self.effect_ref)
        ):
            raise ValueError("Exact environment execution pins required")


@dataclass(frozen=True)
class EnvironmentExecutionManifest:
    workspace: str
    provider: str
    registrations: tuple[EnvironmentExecutionPin, ...]
    digest: str

    def __post_init__(self):
        if (
            not isinstance(self.workspace, str)
            or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", self.workspace)
            or not isinstance(self.provider, str)
            or not _PROVIDER.fullmatch(self.provider)
            or not isinstance(self.registrations, tuple)
            or not 1 <= len(self.registrations) <= 50
            or not all(isinstance(value, EnvironmentExecutionPin) for value in self.registrations)
            or len({value.registration_id for value in self.registrations}) != len(self.registrations)
            or tuple(sorted(self.registrations, key=lambda value: value.registration_id))
            != self.registrations
            or not isinstance(self.digest, str)
            or not _DIGEST.fullmatch(self.digest)
        ):
            raise ValueError("Canonical reviewed environment worker manifest required")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate environment worker manifest field")
        result[key] = value
    return result


def load_environment_execution_manifest(path, *, workspace):
    if not path:
        raise ValueError("Explicit environment execution manifest required")
    with Path(path).open("rb") as source:
        raw = source.read(65537)
    if not raw or len(raw) > 65536:
        raise ValueError("Bounded environment execution manifest required")
    value = json.loads(raw, object_pairs_hook=_unique)
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "profile", "workspace", "provider", "registrations"}
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["profile"] != "reviewed_environment_execution_worker_v1"
        or value["workspace"] != workspace
        or not isinstance(value["registrations"], list)
    ):
        raise ValueError("Invalid reviewed environment worker manifest")
    fields = {
        "registration_id",
        "execution_revision",
        "application_id",
        "resource_verifier_ref",
        "effect_ref",
    }
    pins = []
    for item in value["registrations"]:
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError("Exact environment execution registration required")
        pins.append(EnvironmentExecutionPin(**item))
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()
    return EnvironmentExecutionManifest(
        value["workspace"],
        value["provider"],
        tuple(pins),
        hashlib.sha256(canonical).hexdigest(),
    )


def environment_execution_entry_points(provider, *, entry_points=None):
    if not isinstance(provider, str) or not _PROVIDER.fullmatch(provider):
        raise ValueError("Registered environment composition provider required")
    values = metadata.entry_points() if entry_points is None else entry_points
    if hasattr(values, "select"):
        matches = tuple(values.select(group=ENTRY_POINT_GROUP, name=provider))
    else:
        matches = tuple(
            value for value in values if value.group == ENTRY_POINT_GROUP and value.name == provider
        )
    if len(matches) != 1:
        raise ValueError("Exactly one installed environment composition provider required")
    return matches


def compose_environment_executions(manifest, *, entry_points=None):
    if not isinstance(manifest, EnvironmentExecutionManifest):
        raise TypeError("Reviewed environment worker manifest required")
    (entry_point,) = environment_execution_entry_points(manifest.provider, entry_points=entry_points)
    provider = entry_point.load()
    if not callable(provider):
        raise TypeError("Environment composition provider must be callable")
    selected = tuple(value.registration_id for value in manifest.registrations)
    compositions = provider(selected)
    if not isinstance(compositions, tuple) or len(compositions) != len(selected):
        raise ValueError("Provider returned a different environment composition set")
    by_id = {}
    for composition in compositions:
        if not isinstance(composition, RegisteredEnvironmentExecutionComposition):
            raise TypeError("Provider returned an invalid environment composition")
        identity = composition.execution.job.id
        if identity in by_id:
            raise ValueError("Provider returned duplicate environment composition")
        by_id[identity] = composition
    if set(by_id) != set(selected):
        raise ValueError("Provider returned an unapproved environment composition")
    for pin in manifest.registrations:
        composition = by_id[pin.registration_id]
        execution = composition.execution
        if (
            execution.revision != pin.execution_revision
            or execution.job.transfer.source.application_id != pin.application_id
            or composition.resource_verifier_ref != pin.resource_verifier_ref
            or composition.effect_ref != pin.effect_ref
        ):
            raise ValueError("Installed environment composition differs from operator pins")
    return tuple(by_id[value] for value in selected)
