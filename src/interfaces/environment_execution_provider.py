"""Inspect an installed environment provider artifact without importing it."""

import argparse
import json

from interfaces.environment_execution_registration import (
    attest_environment_execution_provider,
    environment_execution_entry_points,
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--provider", required=True)
    args = parser.parse_args(argv)
    try:
        (entry_point,) = environment_execution_entry_points(args.provider)
        pin = attest_environment_execution_provider(entry_point)
    except Exception:  # noqa: BLE001 -- local package paths stay private
        parser.exit(1, "Environment provider artifact inspection failed.\n")
    print(
        json.dumps(
            {
                "schema_version": 1,
                "profile": "reviewed_environment_provider_artifact_v1",
                **pin.document(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        flush=True,
    )
