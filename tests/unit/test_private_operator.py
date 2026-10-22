"""Private authentication at actual HTTP and CLI boundaries, with no AWS calls."""

import base64
import json
import threading
from email.message import Message
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from unittest.mock import Mock, patch

import pytest

from domain.access import AccessResult, Action, LoginSource, record_access
from interfaces.b_runtime import main
from interfaces.http.deployment_preparation import DatabasePreparationApp, handler_for_preparation
from interfaces.http.private_operator import PrivateOperatorAuthenticator

DOCUMENT = json.dumps({"user_id": "operator", "organization_id": "personal", "password": "x" * 43})


def identity(port=8080):
    return PrivateOperatorAuthenticator.from_json(
        DOCUMENT, host="127.0.0.1", port=port, origin=f"http://127.0.0.1:{port}"
    )


def headers(*, credential="operator:" + "x" * 43, host="127.0.0.1:8080"):
    result = Message()
    result["Host"] = host
    result["Authorization"] = "Basic " + base64.b64encode(credential.encode()).decode()
    return result


def test_identity_does_not_grant_legacy_or_foreign_ownership():
    actor = identity().authenticate_request(headers())
    assert actor.login_source is LoginSource.PRIVATE_OPERATOR
    assert record_access(actor, Action.READ, {}) is AccessResult.NOT_FOUND
    assert (
        record_access(actor, Action.READ, {"organization_id": "other", "created_by": "operator"})
        is AccessResult.NOT_FOUND
    )
    assert (
        record_access(actor, Action.DEPLOY, {"organization_id": "personal", "created_by": "operator"})
        is AccessResult.GRANTED
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("Host", "evil.test"),
        ("Authorization", "Basic !!!"),
        ("Authorization", "Bearer forged"),
        ("Authorization", "Basic " + base64.b64encode(b"operator:wrong").decode()),
    ],
)
def test_invalid_credentials_and_host_are_rejected(field, value):
    request = headers()
    request.replace_header(field, value)
    assert identity().authenticate_request(request) is None


@pytest.mark.parametrize("name", ["Authorization", "Host"])
def test_duplicate_security_headers_rejected(name):
    request = headers()
    request[name] = request[name]
    assert identity().authenticate_request(request) is None


@pytest.mark.parametrize(
    "host,origin,port",
    [
        ("0.0.0.0", "http://127.0.0.1:8080", 8080),
        ("localhost", "http://localhost:8080", 8080),
        ("127.0.0.1", "https://example.com", 8080),
        ("127.0.0.1", "http://127.0.0.1:8081", 8080),
        ("127.0.0.1", "http://127.0.0.1:0", 0),
    ],
)
def test_non_loopback_or_mismatched_configuration_refused(host, origin, port):
    with pytest.raises(ValueError):
        PrivateOperatorAuthenticator.from_json(DOCUMENT, host=host, port=port, origin=origin)


@pytest.mark.parametrize(
    "document",
    [
        None,
        "{}",
        '{"password":"secret","password":"other"}',
        DOCUMENT.replace("x" * 43, "short"),
        DOCUMENT.replace('"operator"', '"bad:user"'),
    ],
)
def test_unsafe_configuration_fails_without_disclosing_document(document):
    with pytest.raises(ValueError, match="Invalid private operator configuration"):
        PrivateOperatorAuthenticator.from_json(
            document, host="127.0.0.1", port=8080, origin="http://127.0.0.1:8080"
        )


def test_browser_challenge_authorized_page_and_cross_origin_write_denial():
    preparation = Mock()
    app = DatabasePreparationApp(
        Mock(), Mock(), preparation, authenticator=identity(), origin="http://127.0.0.1:8080"
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for_preparation(app))
    port = server.server_port
    app.authenticator = identity(port)
    app.origin = f"http://127.0.0.1:{port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def request(method, path, values=None):
        connection = HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.request(method, path, headers=values or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    try:
        status, response_headers, body = request("GET", "/prepare")
        assert status == 401 and response_headers["WWW-Authenticate"].startswith("Basic ") and not body
        auth = {"Authorization": headers()["Authorization"]}
        assert request("GET", "/prepare", auth)[0] == 200
        status, _, body = request("GET", "/api/config", auth)
        assert status == 200 and json.loads(body)["upload_enabled"] is True
        assert request("POST", "/api/deployment-previews", {**auth, "Origin": "https://evil.test"})[0] == 403
        assert request("GET", "/api/config", {**auth, "X-Sky-Token": "legacy"})[0] == 403
        preparation.upload.assert_not_called()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


@pytest.mark.parametrize(
    "extra",
    [
        [],
        ["--enable-preparation"],
        ["--enable-preparation", "--host", "0.0.0.0", "--origin", "http://127.0.0.1:8080"],
    ],
)
def test_cli_rejects_private_mode_before_runtime_or_aws(extra):
    with (
        patch.dict("os.environ", {"SKY_PRIVATE_OPERATOR_JSON": DOCUMENT}, clear=True),
        patch("interfaces.b_preparation_runtime.run_preparation_api") as run,
        pytest.raises(SystemExit),
    ):
        main(["api", "--auth-mode", "private-operator", *extra])
    run.assert_not_called()


def test_cli_private_mode_explicit_dispatch_and_mixed_alb_denial():
    options = [
        "api",
        "--auth-mode",
        "private-operator",
        "--enable-preparation",
        "--host",
        "127.0.0.1",
        "--origin",
        "http://127.0.0.1:8080",
    ]
    with (
        patch.dict("os.environ", {"SKY_PRIVATE_OPERATOR_JSON": DOCUMENT}, clear=True),
        patch("interfaces.b_preparation_runtime.run_preparation_api") as run,
    ):
        main(options)
        assert run.call_count == 1
        with pytest.raises(SystemExit):
            main([*options, "--alb-trusts-file", "trust.json", "--memberships-file", "members.json"])
        assert run.call_count == 1


def test_alb_mode_does_not_consume_private_operator_credentials():
    from argparse import Namespace

    from interfaces.b_preparation_runtime import preparation_identity

    with (
        patch.dict("os.environ", {"SKY_PRIVATE_OPERATOR_JSON": DOCUMENT}, clear=True),
        pytest.raises(ValueError, match="explicit private-operator mode"),
    ):
        preparation_identity(Namespace(auth_mode="alb", alb_trusts_file=None, memberships_file=None))
