"""Validate a trusted Python inventory with pinned official schemas, offline only."""

import argparse
import hashlib
import json
from pathlib import Path

from jsonschema import Draft7Validator, FormatChecker
from referencing import Registry, Resource

SCHEMA_COMMIT = "55343ba19dee1785acf1ce9191540d5fd7b590db"
PINNED_SHA256 = {
    "bom-1.6.schema.json": "3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93",
    "spdx.schema.json": "baa9d3bd1ed57b6751b0887edead6b5063ff53ff7429cf85d476c6c94af0166e",
    "jsf-0.82.schema.json": "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae",
}


def validate(document, schema_directory):
    if (
        not isinstance(document, dict)
        or document.get("bomFormat") != "CycloneDX"
        or document.get("specVersion") != "1.6"
    ):
        raise ValueError("CycloneDX 1.6 document required")
    if len(json.dumps(document).encode()) > 1024 * 1024:
        raise ValueError("SBOM exceeds bounded trusted inventory scope")
    schemas = {}
    for name, expected in PINNED_SHA256.items():
        path = schema_directory / name
        if path.is_symlink():
            raise ValueError("Pinned schema must be a regular file")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("Official schema bytes differ from the pinned revision")
        schema = json.loads(raw)
        Draft7Validator.check_schema(schema)
        schemas[name] = schema
    # No network retriever is registered. Unknown references fail closed instead
    # of contacting a schema URL derived from an untrusted document.
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas.values()
    )
    validator = Draft7Validator(
        schemas["bom-1.6.schema.json"], registry=registry, format_checker=FormatChecker()
    )
    if next(validator.iter_errors(document), None) is not None:
        raise ValueError("SBOM violates the pinned official CycloneDX schema")
    return {
        "status": "schema_valid",
        "schema_revision": SCHEMA_COMMIT,
        "external_reference_fetches": 0,
        "scope": "trusted-installed-python-environment-only",
        "complete_os_inventory_claimed": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument(
        "--schema-directory",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "security/schemas/cyclonedx-1.6",
    )
    args = parser.parse_args(argv)
    try:
        with args.input.open("rb") as source:
            raw = source.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("SBOM too large")
        result = validate(json.loads(raw), args.schema_directory)
    except Exception:  # noqa: BLE001 -- inventory data need not enter console errors
        parser.exit(1, "SBOM schema validation failed or unavailable.\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
