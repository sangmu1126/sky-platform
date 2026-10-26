"""Optional trusted operator policy and local signed bundle; never project input."""

import json
from dataclasses import fields
from pathlib import Path

from adapters.github.recovery_provenance import bounded_file, unique
from domain.recovery_provenance import RecoveryProvenancePolicy


def load_recovery_provenance_registration(path):
    value = json.loads(bounded_file(path, 16384), object_pairs_hook=unique)
    names = {field.name for field in fields(RecoveryProvenancePolicy)}
    if (
        not isinstance(value, dict)
        or set(value) != names | {"version", "bundle", "trusted_root"}
        or (type(value["version"]) is not int or value["version"] != 1)
    ):
        raise ValueError("Exact operator provenance registration required")
    policy = RecoveryProvenancePolicy(**{k: value[k] for k in names})
    paths = {}
    for key in ("bundle", "trusted_root"):
        if not isinstance(value[key], str) or not value[key] or len(value[key]) > 4096:
            raise ValueError("Explicit operator attestation input path required")
        candidate = Path(value[key])
        paths[key] = candidate if candidate.is_absolute() else Path(path).resolve().parent / candidate
    return policy, paths
