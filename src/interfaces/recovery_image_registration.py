"""Explicit operator-owned file only; never load provenance from uploaded projects."""

import json
from dataclasses import fields
from pathlib import Path

from domain.recovery_image import RecoveryImageRegistration


def load_recovery_image_registration(path):
    if not path:
        raise ValueError("Explicit recovery image registration file required")
    with Path(path).open("rb") as stream:
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ValueError("Recovery image registration exceeds size bound")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate recovery image registration field")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=unique)
    if (
        not isinstance(value, dict)
        or set(value) != {"version", *(f.name for f in fields(RecoveryImageRegistration))}
        or type(value["version"]) is not int
        or value["version"] != 1
    ):
        raise ValueError("Exact versioned recovery registration required")
    value.pop("version")
    return RecoveryImageRegistration(**value)
