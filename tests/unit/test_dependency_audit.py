"""Vulnerability feed failures cannot become a clean supply-chain result."""

import io
import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from scripts.audit_python_dependencies import inventory, query


def test_inventory_is_metadata_only_and_normalizes_names():
    packages = inventory([SimpleNamespace(metadata={"Name": "my_package"}, version="1.0")])
    assert packages == [{"name": "my-package", "version": "1.0"}]


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
