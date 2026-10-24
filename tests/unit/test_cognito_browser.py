"""Public login shell must not make private API data public."""

import json
import threading
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from unittest.mock import Mock

import pytest

from interfaces.http.cognito_browser import CognitoBrowser
from interfaces.http.cognito_identity import CognitoSettings
from interfaces.http.deployment_preparation import DatabasePreparationApp, handler_for_preparation

ISSUER = "https://cognito-idp.ap-northeast-2.amazonaws.com/ap-northeast-2_TestPool"
DOMAIN = "https://sky-personal.auth.ap-northeast-2.amazoncognito.com"
ORIGIN = "https://sky.example.test"
IDENTITY = CognitoSettings(ISSUER, "client123", ("sky/deploy",))


@pytest.mark.parametrize(
    "domain",
    [
        "http://evil.test",
        DOMAIN + "/",
        DOMAIN + "?next=evil",
        DOMAIN.replace("ap-northeast-2", "us-east-1"),
        "https://user:pass@" + DOMAIN[8:],
    ],
)
def test_login_domain_must_be_configured_regional_cognito(domain):
    with pytest.raises(ValueError):
        CognitoBrowser(domain, ORIGIN, IDENTITY)


@pytest.mark.parametrize(
    "origin", ["http://sky.example.test", ORIGIN + "/", ORIGIN + "?x=1", "https://user:pass@sky.example.test"]
)
def test_login_callback_requires_exact_https_application_origin(origin):
    with pytest.raises(ValueError):
        CognitoBrowser(DOMAIN, origin, IDENTITY)


def test_only_static_login_and_shell_are_public(capsys):
    auth = Mock()
    auth.authenticate_request.return_value = None
    reads, approvals, preparation = Mock(), Mock(), Mock()
    app = DatabasePreparationApp(reads, approvals, preparation, authenticator=auth, origin=ORIGIN)
    app.cognito_browser = CognitoBrowser(DOMAIN, ORIGIN, IDENTITY)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for_preparation(app))
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()

    def get(path):
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        try:
            connection.request("GET", path)
            r = connection.getresponse()
            return r.status, dict(r.getheaders()), r.read()
        finally:
            connection.close()

    try:
        status, headers, body = get("/auth/config")
        assert status == 200 and headers["Cache-Control"] == "no-store"
        doc = json.loads(body)
        assert doc["redirect_uri"] == ORIGIN + "/auth/callback" and doc["scopes"] == ["openid", "sky/deploy"]
        assert "secret" not in body.decode() and "password" not in body.decode()
        status, headers, body = get("/login")
        assert status == 200 and b'id="sky-login"' in body and headers["Referrer-Policy"] == "no-referrer"
        assert get("/auth/client.js")[0] == 200
        status, headers, body = get("/auth/callback?code=sensitive-code&state=sensitive-state")
        assert status == 200 and b"/auth/client.js" in body and b"sensitive-code" not in body
        assert get("/api/config")[0] == 403
        assert get("/api/jobs/unknown")[0] == 403
        reads.detail.assert_not_called()
        preparation.deploy.assert_not_called()
    finally:
        server.shutdown()
        server.server_close()
        worker.join(5)
    logs = capsys.readouterr().err
    assert "sensitive-code" not in logs and "sensitive-state" not in logs
