"""Load trusted operator configuration, never app-supplied role or policy inputs."""

import json
import os
from pathlib import Path

from domain.database import DatabaseBinding
from domain.incident_secret_access import IncidentSecretRegistration


def load_secret_registration(path):
    raw = os.environ.get("SKY_INCIDENT_SECRET_ACCESS_JSON")
    if raw is not None:
        if path:
            raise ValueError("Use a Secret access registration file or environment, not both")
        data = raw.encode()
    elif path:
        with Path(path).open("rb") as stream:
            data = stream.read(32769)
    else:
        raise ValueError("Explicit workload Secret access registration required")
    if len(data) > 32768:
        raise ValueError("Secret access registration exceeds size bound")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate Secret access registration field")
            result[key] = value
        return result

    value = json.loads(data, object_pairs_hook=unique)
    if (
        not isinstance(value, dict)
        or set(value) != {"version", "binding", "resource_id", "secret_arn", "kms_key_arn"}
        or type(value["version"]) is not int
        or value["version"] != 1
        or not isinstance(value["binding"], dict)
    ):
        raise ValueError("Invalid workload Secret access registration")
    return IncidentSecretRegistration(
        binding=DatabaseBinding(**value["binding"]),
        **{key: value[key] for key in ("resource_id", "secret_arn", "kms_key_arn")},
    )
