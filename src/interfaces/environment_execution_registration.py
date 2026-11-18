"""Operator manifest for server-installed reviewed environment compositions."""

import csv
import hashlib
import io
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path, PurePosixPath

from application.environment_execution_composition import (
    RegisteredEnvironmentExecutionComposition,
)

ENTRY_POINT_GROUP = "sky.environment_execution.v1"
_REF = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,127}\Z")
_PROVIDER = re.compile(r"[a-z][a-z0-9-]{2,63}\Z")
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_RESOURCE_REF = re.compile(r"EVR-[a-f0-9]{64}\Z")
_EFFECT_REF = re.compile(r"EEF-[a-f0-9]{64}\Z")
_DISTRIBUTION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+!-]{0,63}\Z")
_INSTALLER_METADATA = {"INSTALLER", "REQUESTED", "direct_url.json"}


@dataclass(frozen=True)
class EnvironmentProviderArtifact:
    provider: str
    distribution: str
    version: str
    artifact_sha256: str

    def __post_init__(self):
        if (
            not isinstance(self.provider, str)
            or not _PROVIDER.fullmatch(self.provider)
            or not isinstance(self.distribution, str)
            or not _DISTRIBUTION.fullmatch(self.distribution)
            or not isinstance(self.version, str)
            or not _VERSION.fullmatch(self.version)
            or not isinstance(self.artifact_sha256, str)
            or not _DIGEST.fullmatch(self.artifact_sha256)
        ):
            raise ValueError("Exact installed environment provider artifact required")

    def document(self):
        return {
            "provider": self.provider,
            "provider_distribution": self.distribution,
            "provider_version": self.version,
            "provider_artifact_sha256": self.artifact_sha256,
        }


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
    provider_artifact: EnvironmentProviderArtifact
    registrations: tuple[EnvironmentExecutionPin, ...]
    digest: str

    def __post_init__(self):
        if (
            not isinstance(self.workspace, str)
            or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", self.workspace)
            or not isinstance(self.provider_artifact, EnvironmentProviderArtifact)
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

    @property
    def provider(self):
        return self.provider_artifact.provider


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate environment worker manifest field")
        result[key] = value
    return result


def _manifest_bytes(path):
    try:
        value = Path(path)
    except TypeError:
        raise ValueError("Explicit environment execution manifest required") from None
    if not value.is_absolute():
        raise ValueError("Absolute environment execution manifest required")
    try:
        descriptor = os.open(
            value,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError:
        raise ValueError("Immutable environment execution manifest required") from None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 1 <= before.st_size <= 65536
        ):
            raise ValueError("Immutable bounded environment execution manifest required")
        raw = bytearray()
        while len(raw) <= 65536:
            chunk = os.read(descriptor, min(65537 - len(raw), 65536))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        if len(raw) != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ValueError("Environment execution manifest changed while reading")
        return bytes(raw)
    finally:
        os.close(descriptor)


def load_environment_execution_manifest(path, *, workspace):
    if not path:
        raise ValueError("Explicit environment execution manifest required")
    raw = _manifest_bytes(path)
    value = json.loads(raw, object_pairs_hook=_unique)
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "schema_version",
            "profile",
            "workspace",
            "provider",
            "provider_distribution",
            "provider_version",
            "provider_artifact_sha256",
            "registrations",
        }
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 2
        or value["profile"] != "reviewed_environment_execution_worker_v2"
        or value["workspace"] != workspace
        or not isinstance(value["registrations"], list)
    ):
        raise ValueError("Invalid reviewed environment worker manifest")
    pins = _execution_pins(value["registrations"])
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()
    if raw not in {canonical, canonical + b"\n"}:
        raise ValueError("Canonical environment execution manifest required")
    return EnvironmentExecutionManifest(
        value["workspace"],
        EnvironmentProviderArtifact(
            value["provider"],
            value["provider_distribution"],
            value["provider_version"],
            value["provider_artifact_sha256"],
        ),
        pins,
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


def _provider_file(path, *, maximum):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or before.st_size > maximum
        ):
            raise ValueError("Immutable bounded provider package file required")
        digest = hashlib.sha256()
        content = bytearray()
        size = 0
        while True:
            chunk = os.read(descriptor, min(65536, maximum + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > maximum:
                raise ValueError("Provider package file exceeds bound")
            digest.update(chunk)
            content.extend(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) or size != before.st_size:
            raise ValueError("Provider package changed during inspection")
        return bytes(content), digest.hexdigest()
    finally:
        os.close(descriptor)


def _provider_path(root, relative, distribution):
    candidate = Path(distribution.locate_file(relative))
    expected = root.joinpath(*relative.parts)
    cursor = root
    for part in relative.parts[:-1]:
        cursor /= part
        info = cursor.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise ValueError("Immutable provider package directory required")
    if candidate.is_symlink():
        raise ValueError("Provider package symlinks are forbidden")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError:
        raise ValueError("Provider package file escaped its distribution") from None
    if resolved != expected.resolve(strict=True):
        raise ValueError("Provider package file must remain inside its distribution")
    return candidate


def _provider_relative(raw_path):
    relative = PurePosixPath(raw_path)
    if (
        relative.is_absolute()
        or not relative.parts
        or ".." in relative.parts
        or any(not part or part in {".", ".."} for part in relative.parts)
        or relative.as_posix() != raw_path
        or "\\" in raw_path
        or any(ord(value) < 33 for value in raw_path)
        or len(relative.as_posix().encode()) > 512
    ):
        raise ValueError("Canonical provider distribution path required")
    return relative


def _installer_metadata(relative):
    return (
        len(relative.parts) >= 2
        and relative.parts[-2].endswith(".dist-info")
        and relative.name in _INSTALLER_METADATA
    )


def _provider_record(content, paths, record_path):
    try:
        rows = list(csv.reader(io.StringIO(content.decode())))
    except (UnicodeError, csv.Error):
        raise ValueError("Canonical provider RECORD required") from None
    values = {}
    for row in rows:
        if len(row) != 3:
            raise ValueError("Canonical provider RECORD required")
        relative = _provider_relative(row[0])
        name = relative.as_posix()
        if name in values:
            raise ValueError("Canonical provider RECORD required")
        digest, size = row[1:]
        if name == record_path:
            if digest or size:
                raise ValueError("Canonical provider RECORD required")
        elif digest:
            if not re.fullmatch(r"sha256=[A-Za-z0-9_-]{43}", digest) or not re.fullmatch(
                r"0|[1-9][0-9]{0,9}", size
            ):
                raise ValueError("Canonical provider RECORD required")
        elif size:
            raise ValueError("Canonical provider RECORD required")
        values[name] = (digest, size)
    if set(values) != paths or record_path not in values:
        raise ValueError("Provider RECORD differs from installed distribution")
    return [
        {"path": name, "digest": values[name][0], "size": values[name][1]}
        for name in sorted(values)
        if not _installer_metadata(PurePosixPath(name))
    ]


def _reject_provider_bytecode(root, module, paths):
    if any(value.suffix == ".pyc" or "__pycache__" in value.parts for value in paths):
        raise ValueError("Provider bytecode caches are forbidden")
    top = module.split(".", 1)[0]
    package = root / top
    if package.is_dir():
        prefix = top + "/"
        expected = {value for value in paths if value.as_posix().startswith(prefix)}
        observed = set()
        for value in package.rglob("*"):
            relative = PurePosixPath(value.relative_to(root).as_posix())
            info = value.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ValueError("Provider package symlinks are forbidden")
            if value.is_file():
                observed.add(relative)
        if observed != expected:
            raise ValueError("Provider package tree differs from distribution RECORD")
    else:
        cache = root / "__pycache__"
        if cache.is_dir() and any(cache.glob(top + ".*.pyc")):
            raise ValueError("Provider bytecode caches are forbidden")


def attest_environment_execution_provider(entry_point):
    """Hash an installed provider distribution without importing its code."""
    if (
        getattr(entry_point, "group", None) != ENTRY_POINT_GROUP
        or not isinstance(getattr(entry_point, "name", None), str)
        or not _PROVIDER.fullmatch(entry_point.name)
        or not isinstance(getattr(entry_point, "value", None), str)
        or not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*:[A-Za-z_]\w*", entry_point.value)
    ):
        raise ValueError("Exact environment provider entry point required")
    distribution = getattr(entry_point, "dist", None)
    name = None if distribution is None else distribution.metadata.get("Name")
    version = None if distribution is None else distribution.version
    pin = EnvironmentProviderArtifact(entry_point.name, name, version, "0" * 64)
    files = () if distribution.files is None else tuple(distribution.files)
    if not 3 <= len(files) <= 512:
        raise ValueError("Bounded installed provider distribution required")
    root = Path(distribution.locate_file("")).resolve(strict=True)
    root_info = root.stat()
    if not stat.S_ISDIR(root_info.st_mode) or root_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("Immutable provider distribution root required")
    records = []
    total = 0
    paths = set()
    relatives = []
    for item in files:
        raw_path = str(item)
        relative = _provider_relative(raw_path)
        if relative.as_posix() in paths:
            raise ValueError("Canonical provider distribution path required")
        paths.add(relative.as_posix())
        relatives.append(relative)
    record_paths = [
        value for value in relatives if value.name == "RECORD" and value.parent.name.endswith(".dist-info")
    ]
    if len(record_paths) != 1:
        raise ValueError("Exactly one provider RECORD required")
    record_path = record_paths[0].as_posix()
    record_content, _record_digest = _provider_file(
        _provider_path(root, record_paths[0], distribution), maximum=1024 * 1024
    )
    canonical_record = _provider_record(record_content, paths, record_path)
    module = entry_point.value.split(":", 1)[0]
    _reject_provider_bytecode(root, module, tuple(relatives))
    for relative in relatives:
        candidate = _provider_path(root, relative, distribution)
        content, digest = _provider_file(candidate, maximum=1024 * 1024)
        size = len(content)
        total += size
        if total > 16 * 1024 * 1024:
            raise ValueError("Provider distribution exceeds bound")
        if relative.as_posix() == record_path or _installer_metadata(relative):
            continue
        records.append({"path": relative.as_posix(), "size": size, "sha256": digest})
    module_path = module.replace(".", "/")
    if not ({module_path + ".py", module_path + "/__init__.py"} & paths):
        raise ValueError("Entry point module is absent from provider distribution")
    if not any(path.endswith(".dist-info/METADATA") for path in paths) or not any(
        path.endswith(".dist-info/entry_points.txt") for path in paths
    ):
        raise ValueError("Provider distribution metadata is incomplete")
    payload = {
        "schema_version": 1,
        "profile": "reviewed_environment_provider_artifact_v1",
        "provider": pin.provider,
        "distribution": pin.distribution,
        "version": pin.version,
        "entry_point": entry_point.value,
        "files": sorted(records, key=lambda value: value["path"]),
        "record": canonical_record,
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    return EnvironmentProviderArtifact(pin.provider, pin.distribution, pin.version, digest)


def _provider_descriptor_path(entry_point):
    distribution = entry_point.dist
    matches = tuple(
        PurePosixPath(str(value))
        for value in distribution.files
        if str(value).endswith(".dist-info/sky-environment-executions-v1.json")
    )
    if len(matches) != 1:
        raise ValueError("Exactly one provider execution descriptor required")
    root = Path(distribution.locate_file("")).resolve(strict=True)
    return _provider_path(root, matches[0], distribution)


def _execution_pins(values):
    fields = {
        "registration_id",
        "execution_revision",
        "application_id",
        "resource_verifier_ref",
        "effect_ref",
    }
    if not isinstance(values, list) or not 1 <= len(values) <= 50:
        raise ValueError("Bounded environment execution registrations required")
    pins = []
    for item in values:
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError("Exact environment execution registration required")
        pins.append(EnvironmentExecutionPin(**item))
    result = tuple(pins)
    if tuple(sorted(result, key=lambda value: value.registration_id)) != result or len(
        {value.registration_id for value in result}
    ) != len(result):
        raise ValueError("Canonical provider execution registrations required")
    return result


def load_environment_execution_provider_descriptor(entry_point):
    """Load secret-free pins from an already installed and hashed provider package."""
    before = attest_environment_execution_provider(entry_point)
    content, _digest = _provider_file(_provider_descriptor_path(entry_point), maximum=65536)
    value = json.loads(content, object_pairs_hook=_unique)
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "profile", "provider", "registrations"}
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["profile"] != "reviewed_environment_provider_executions_v1"
        or value["provider"] != entry_point.name
    ):
        raise ValueError("Invalid provider execution descriptor")
    pins = _execution_pins(value["registrations"])
    if attest_environment_execution_provider(entry_point) != before:
        raise ValueError("Provider package changed while reading execution descriptor")
    return before, pins


def render_environment_execution_manifest(provider, workspace, *, entry_points=None):
    if not isinstance(workspace, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", workspace):
        raise ValueError("Registered environment workspace required")
    (entry_point,) = environment_execution_entry_points(provider, entry_points=entry_points)
    artifact, pins = load_environment_execution_provider_descriptor(entry_point)
    return {
        "schema_version": 2,
        "profile": "reviewed_environment_execution_worker_v2",
        "workspace": workspace,
        **artifact.document(),
        "registrations": [
            {
                "registration_id": value.registration_id,
                "execution_revision": value.execution_revision,
                "application_id": value.application_id,
                "resource_verifier_ref": value.resource_verifier_ref,
                "effect_ref": value.effect_ref,
            }
            for value in pins
        ],
    }


def verify_environment_execution_descriptor(manifest, entry_point):
    artifact, pins = load_environment_execution_provider_descriptor(entry_point)
    if artifact != manifest.provider_artifact or pins != manifest.registrations:
        raise ValueError("Provider execution descriptor differs from operator manifest")
    return pins


def verify_environment_execution_provider(manifest, entry_point):
    if not isinstance(manifest, EnvironmentExecutionManifest):
        raise TypeError("Reviewed environment worker manifest required")
    observed = attest_environment_execution_provider(entry_point)
    if observed != manifest.provider_artifact:
        raise ValueError("Installed environment provider artifact differs from operator pin")
    return observed


def compose_environment_executions(manifest, *, entry_points=None):
    if not isinstance(manifest, EnvironmentExecutionManifest):
        raise TypeError("Reviewed environment worker manifest required")
    (entry_point,) = environment_execution_entry_points(manifest.provider, entry_points=entry_points)
    verify_environment_execution_provider(manifest, entry_point)
    verify_environment_execution_descriptor(manifest, entry_point)
    sys.dont_write_bytecode = True
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
    verify_environment_execution_provider(manifest, entry_point)
    return tuple(by_id[value] for value in selected)
