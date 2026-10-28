"""Vulnerability feed failures cannot become a clean supply-chain result."""

import io
import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from scripts.audit_python_dependencies import cyclonedx, inventory, query


def test_inventory_is_metadata_only_and_normalizes_names():
    packages = inventory([SimpleNamespace(metadata={"Name": "my_package"}, version="1.0")])
    assert packages == [{"name": "my-package", "version": "1.0"}]


def test_cyclonedx_scope_contains_inventory_without_invented_evidence():
    packages = inventory([SimpleNamespace(metadata={"Name": "my_package"}, version="1.0+local")])
    document = cyclonedx(packages, observed_at="2026-10-29T00:00:00Z")
    assert document["bomFormat"] == "CycloneDX" and document["specVersion"] == "1.6"
    assert document["components"] == [
        {
            "type": "library",
            "name": "my-package",
            "version": "1.0+local",
            "purl": "pkg:pypi/my-package@1.0%2Blocal",
            "bom-ref": "pkg:pypi/my-package@1.0%2Blocal",
        }
    ]
    assert "dependencies" not in document and "vulnerabilities" not in document
    assert "hashes" not in document["components"][0] and "licenses" not in document["components"][0]


@pytest.mark.parametrize(
    "response",
    [
        {},
        {"results": []},
        {"results": [{"next_page_token": "more"}]},
        {"results": [{"error": {"code": 503}}]},
        {"results": [{"vulns": [{"id": "<script>"}]}]},
    ],
)
def test_missing_or_truncated_feed_is_not_clean(response):
    stream = io.BytesIO(json.dumps(response).encode())
    opener = Mock()
    opener.open.return_value = stream
    with patch("urllib.request.build_opener", return_value=opener), pytest.raises(ValueError):
        query([{"name": "example", "version": "1.0"}])


def test_known_findings_are_not_discarded():
    stream = io.BytesIO(b'{"results":[{"vulns":[{"id":"GHSA-synthetic-example"}]}]}')
    opener = Mock()
    opener.open.return_value = stream
    with patch("urllib.request.build_opener", return_value=opener):
        result = query([{"name": "example", "version": "1.0"}])
    assert result[0]["vulnerabilities"] == ["GHSA-synthetic-example"]
    assert opener.open.call_args.args[0].full_url == "https://api.osv.dev/v1/querybatch"
