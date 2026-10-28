"""Synthetic transport checks: no API key or actual model invocation."""

import io
import json
import urllib.error
import urllib.request
from unittest.mock import patch

import pytest

from adapters.ai.openai_http import OpenAIHTTPFailure, read_response
from application.analysis import source_context


@pytest.mark.parametrize(
    "url",
    [
        "http://api.openai.com/v1/responses",
        "https://api.openai.com.attacker.invalid/v1/responses",
        "https://api.openai.com@attacker.invalid/v1/responses",
        "https://api.openai.com/v1/responses?next=other",
        "https://api.openai.com:443/v1/responses",
        "http://169.254.169.254/latest/meta-data/",
        "https://example.invalid/collect",
        "https://api.openai.com/v1/responses#fragment",
    ],
)
def test_untrusted_endpoint_is_rejected_before_transport_creation(url):
    request = urllib.request.Request(url, data=b"{}", headers={"Authorization": "Bearer synthetic-canary"})
    with patch("urllib.request.build_opener") as opener, pytest.raises(ValueError, match="fixed endpoint"):
        read_response(request)
    opener.assert_not_called()


def test_response_redirect_never_retries_to_another_credential_sink():
    request = urllib.request.Request("https://api.openai.com/v1/responses", data=b"{}")
    failure = urllib.error.HTTPError(
        request.full_url, 307, "redirect", {"Location": "https://example.invalid/collect"}, io.BytesIO(b"{}")
    )
    with patch("urllib.request.build_opener") as factory:
        factory.return_value.open.side_effect = failure
        with pytest.raises(OpenAIHTTPFailure):
            read_response(request)
        assert factory.return_value.open.call_count == 1
        assert factory.call_args.args[0].redirect_request(None, None, None, None, None, None) is None


def test_request_and_response_log_artifacts_do_not_contain_known_source_credentials(tmp_path):
    canary = "sk-" + "LOCAL_SYNTHETIC_SECRET_CANARY_" * 3
    (tmp_path / ".env").write_text("OPENAI_API_KEY=" + canary)
    (tmp_path / "app.py").write_text("API_KEY = '" + canary + "'\nprint('hello')")
    context = source_context(tmp_path)
    assert ".env" not in context
    payload = json.dumps({"model": "synthetic", "input": context}).encode()
    assert canary.encode() not in payload
    request = urllib.request.Request("https://api.openai.com/v1/responses", data=payload)
    with patch("urllib.request.build_opener") as factory:
        factory.return_value.open.return_value = io.BytesIO(b'{"status":"completed"}')
        assert read_response(request) == b'{"status":"completed"}'
        assert canary.encode() not in factory.return_value.open.call_args.args[0].data


def test_oversized_request_never_creates_transport():
    request = urllib.request.Request("https://api.openai.com/v1/responses", data=b"x" * (1024 * 1024 + 1))
    with patch("urllib.request.build_opener") as factory, pytest.raises(ValueError):
        read_response(request)
    factory.assert_not_called()


@pytest.mark.parametrize(
    "configuration",
    [
        {"SKY_REQUIRE_EFFECT_BUDGETS": "true"},
        {"SKY_REQUIRE_EFFECT_BUDGETS": "invalid"},
        {"SKY_EFFECT_BUDGET_JSON": "{}"},
    ],
)
def test_unmetered_legacy_model_path_cannot_bypass_hosted_budget(configuration):
    request = urllib.request.Request("https://api.openai.com/v1/responses", data=b"{}")
    with (
        patch.dict("os.environ", configuration),
        patch("urllib.request.build_opener") as factory,
        pytest.raises(ValueError, match="durable operation budget"),
    ):
        read_response(request)
    factory.assert_not_called()
