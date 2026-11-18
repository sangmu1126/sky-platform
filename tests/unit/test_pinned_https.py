"""Registered TLS endpoints have one canonical DNS authority and request path."""

import pytest

from adapters.runtime.pinned_https import pinned_https_endpoint


@pytest.mark.parametrize(
    ("value", "host", "port", "path"),
    [
        ("https://controller.example.test/control", "controller.example.test", 443, "/control"),
        (
            "https://gateway.rehearsal.test:8443/api/scoreboard",
            "gateway.rehearsal.test",
            8443,
            "/api/scoreboard",
        ),
        ("https://api.internal.test/", "api.internal.test", 443, "/"),
        ("https://a.b:443/status_v1", "a.b", 443, "/status_v1"),
    ],
)
def test_canonical_https_endpoint_preserves_exact_sni_authority_and_path(value, host, port, path):
    endpoint, observed_port = pinned_https_endpoint(value)
    assert (endpoint.hostname, observed_port, endpoint.path) == (host, port, path)


@pytest.mark.parametrize(
    "value",
    [
        "http://controller.example.test/control",
        "HTTPS://controller.example.test/control",
        "https://Controller.example.test/control",
        "https://controller..example.test/control",
        "https://-controller.example.test/control",
        "https://controller-.example.test/control",
        "https://localhost/control",
        "https://127.0.0.1/control",
        "https://[::1]/control",
        "https://[invalid/control",
        "https://user@controller.example.test/control",
        "https://controller.example.test",
        "https://controller.example.test//control",
        "https://controller.example.test/./control",
        "https://controller.example.test/../control",
        "https://controller.example.test/%2e%2e/control",
        "https://controller.example.test/con\trol",
        "https://controller.example.test/con\ntrol",
        "https://controller.example.test/control?next=/other",
        "https://controller.example.test/control#fragment",
        "https://controller.example.test:0/control",
        "https://controller.example.test:70000/control",
        None,
    ],
)
def test_ambiguous_non_dns_or_noncanonical_https_endpoint_is_rejected(value):
    with pytest.raises(ValueError, match="Canonical pinned HTTPS endpoint"):
        pinned_https_endpoint(value)
