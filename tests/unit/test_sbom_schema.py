"""Pinned schema validation is offline; malformed inventories are not a valid SBOM."""

import shutil
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

pytest.importorskip("jsonschema")

from scripts.audit_python_dependencies import cyclonedx
from scripts.validate_sbom import validate

SCHEMAS = Path(__file__).resolve().parents[2] / "security/schemas/cyclonedx-1.6"


def test_generated_inventory_passes_official_schema_without_network():
    document = cyclonedx(
        [{"name": "test-package", "version": "1.0"}], observed_at=datetime.now(UTC).isoformat()
    )
    with patch("urllib.request.urlopen", side_effect=AssertionError("No external reference fetch")):
        assert validate(document, SCHEMAS)["external_reference_fetches"] == 0
    document["components"][0]["type"] = "not-a-cyclonedx-type"
    with pytest.raises(ValueError, match="schema"):
        validate(document, SCHEMAS)


def test_replaced_schema_cannot_add_external_resolver_or_relax_validation(tmp_path):
    root = tmp_path / "schemas"
    shutil.copytree(SCHEMAS, root)
    (root / "bom-1.6.schema.json").write_text('{"$ref":"https://untrusted.invalid/schema"}')
    with (
        patch("urllib.request.urlopen", side_effect=AssertionError("No external reference fetch")),
        pytest.raises(ValueError, match="pinned revision"),
    ):
        validate(cyclonedx([], observed_at=datetime.now(UTC).isoformat()), root)
