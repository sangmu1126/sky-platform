import json
import threading
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from unittest.mock import Mock

import pytest

from interfaces.http.server import App, handler_for


@pytest.fixture
def api(tmp_path):
    app = App(tmp_path, monitor_interval=0, github_poll_interval=0)
    service = Mock()
    service.list.return_value = [{"id": "tug-game", "full_v4_qualified": False}]
    service.detail.return_value = {"id": "tug-game"}
    service.submit.return_value = {"id": "opaque-operation", "status": "queued"}
    app.environment_transfers = service
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(app))
    app.origin = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def request(method, path="/api/environment-transfers/tug-game", body=None, headers=None):
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        values = {"X-Sky-Token": app.token, "Origin": app.origin, "Content-Type": "application/json"}
        values.update(headers or {})
        connection.request(method, path, json.dumps(body) if body is not None else None, values)
        response = connection.getresponse()
        data = response.read()
        connection.close()
        return response.status, data

    yield app, service, request
    server.shutdown()
    server.server_close()
    thread.join(5)


def body():
    return {
        "action": "transfer",
        "review_revision": "a" * 64,
        "request_key": "one",
        "confirm_write_pause": True,
        "confirm_websocket_reconnect": True,
    }


def test_existing_sky_page_and_authenticated_async_intake_are_connected(api):
    _, service, request = api
    status, content = request("GET", "/")
    assert status == 200 and b"environmentTransferSection" in content
    status, content = request("POST", body=body())
    assert status == 202 and json.loads(content)["status"] == "queued"
    service.submit.assert_called_once()
    assert request("GET", "/api/environment-transfers")[0] == 200


@pytest.mark.parametrize(
    "headers,status", [({"X-Sky-Token": "foreign"}, 403), ({"Origin": "https://foreign.example"}, 403)]
)
def test_untrusted_requests_never_reach_intake(api, headers, status):
    _, service, request = api
    assert request("POST", body=body(), headers=headers)[0] == status
    service.submit.assert_not_called()


def test_unregistered_commands_credentials_and_targets_are_rejected(api):
    _, service, request = api
    assert request("POST", body={**body(), "command": "docker run", "password": "secret"})[0] == 400
    service.submit.assert_not_called()


def test_scope_and_runtime_exceptions_do_not_disclose_secrets(api):
    _, service, request = api
    service.detail.side_effect = PermissionError("private-db-password")
    status, content = request("GET")
    assert status == 404 and b"private-db-password" not in content
    service.submit.side_effect = OSError("postgres://secret")
    status, content = request("POST", body=body())
    assert status == 503 and b"postgres://secret" not in content
