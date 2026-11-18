"""Render a worker manifest from an installed provider's secret-free descriptor."""

import argparse
import json

from interfaces.environment_execution_registration import render_environment_execution_manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--workspace", required=True)
    args = parser.parse_args(argv)
    try:
        document = render_environment_execution_manifest(args.provider, args.workspace)
    except Exception:  # noqa: BLE001 -- package paths and malformed private metadata stay private
        parser.exit(1, "Environment execution manifest generation failed.\n")
    print(
        json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False),
        flush=True,
    )
