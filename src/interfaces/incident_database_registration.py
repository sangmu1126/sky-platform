"""Load a bounded, operator-owned dedicated incident registration without clients."""

import json
import os
from pathlib import Path

from adapters.aws.dedicated_database import DedicatedDatabaseSettings
from adapters.aws.dedicated_incident import DedicatedIncidentRegistration
from domain.database import DatabaseBinding


def load_dedicated_incident_registration(path, source):
    raw = os.environ.get("SKY_DEDICATED_INCIDENT_JSON")
    if raw is not None:
        if path:
            raise ValueError("Use dedicated incident file or environment, not both")
        data = raw.encode()
    elif path:
        with Path(path).open("rb") as stream:
            data = stream.read(32769)
    else:
        raise ValueError("Explicit dedicated incident registration required")
    if len(data) > 32768:
        raise ValueError("Dedicated incident registration exceeds size bound")

    def unique(pairs):
        document = {}
        for key, value in pairs:
            if key in document:
                raise ValueError("Duplicate incident registration field")
            document[key] = value
        return document

    value = json.loads(data, object_pairs_hook=unique)
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "version",
            "settings",
            "binding",
            "operation_id",
            "plan_id",
            "resource_id",
            "admin_secret_arn",
            "connection_limit",
        }
        or type(value["version"]) is not int
        or value["version"] != 1
        or not isinstance(value["settings"], dict)
        or "source" in value["settings"]
        or not isinstance(value["binding"], dict)
    ):
        raise ValueError("Invalid dedicated incident registration")
    return DedicatedIncidentRegistration(
        settings=DedicatedDatabaseSettings(source=source, **value["settings"]),
        binding=DatabaseBinding(**value["binding"]),
        **{
            key: value[key]
            for key in ("operation_id", "plan_id", "resource_id", "admin_secret_arn", "connection_limit")
        },
    )
