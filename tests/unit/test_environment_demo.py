import http.client
import json
from http.server import ThreadingHTTPServer
from threading import Event, Thread
from unittest.mock import Mock

import pytest

from interfaces.environment_demo import handler_for_environment_demo, public_snapshot


def sample():
    return {
        "active_environment": "aws",
        "app_available": True,
        "writes_blocked": False,
        "rows": [[1, 42]],
        "checked_at": "2026-10-31T00:00:00+09:00",
        "history": [{"label": "AWS → VM", "seconds": 14.1, "outcome": "검증됨"}],
        "operations": [{"kind": "environment_transfer", "status": "failed"}],
        "OPENAI_API_KEY": "not-for-browser",
        "source_password": "not-for-browser",
    }


def test_projection_excludes_unknown_backend_fields_and_never_assumes_live_success():
    value = sample()
    projection = public_snapshot(value)
    assert "not-for-browser" not in json.dumps(projection)
    assert not projection["model_evaluated"] and not projection["full_v4_complete"]
    value["app_available"] = False
    projection = public_snapshot(value)
    assert (
        projection["active_environment"] == "unknown"
        and projection["writes_blocked"] is None
        and projection["rows"] == []
    )
    assert projection["history"]


@pytest.fixture
def web():
    snapshot = Mock(side_effect=sample)
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0), handler_for_environment_demo(snapshot, session_token="a" * 32)
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, snapshot
    server.shutdown()
    server.server_close()
    thread.join(5)


def request(web, path="/", headers=None, method="GET"):
    server, _ = web
    conn = http.client.HTTPConnection(*server.server_address, timeout=3)
    try:
        conn.request(method, path, headers=headers or {})
        response = conn.getresponse()
        body = response.read()
        return response.status, dict(response.getheaders()), body
    finally:
        conn.close()


def test_local_view_uses_httponly_cookie_and_api_requires_same_origin_session(web):
    status, headers, body = request(web)
    assert (
        status == 200 and "HttpOnly" in headers["Set-Cookie"] and "SameSite=Strict" in headers["Set-Cookie"]
    )
    assert ("a" * 32).encode() not in body
    assert request(web, "/api/status")[0] == 403
    status, headers, body = request(web, "/api/status", {"Cookie": "sky_env_demo=" + "a" * 32})
    assert status == 200 and json.loads(body)["active_environment"] == "aws"
    assert b"not-for-browser" not in body and headers["Cache-Control"] == "no-store"
    assert b"innerHTML" not in request(web, "/demo.js")[2]


@pytest.mark.parametrize(
    "headers",
    [{"Host": "rebinding.example:80"}, {"Origin": "https://evil.example"}, {"Sec-Fetch-Site": "cross-site"}],
)
def test_cross_origin_and_host_rebinding_never_query_backend(web, headers):
    assert request(web, "/api/status", {"Cookie": "sky_env_demo=" + "a" * 32, **headers})[0] == 403
    web[1].assert_not_called()


def test_backend_failure_is_redacted_and_no_mutation_endpoint_exists(web):
    web[1].side_effect = OSError("private source credential canary")
    status, _, body = request(web, "/api/status", {"Cookie": "sky_env_demo=" + "a" * 32})
    assert status == 503 and b"canary" not in body
    assert request(web, "/api/transfer", method="POST")[0] == 405


def test_continuity_projection_keeps_pause_evidence_and_removes_raw_client_records():
    value = sample()
    value["continuity"] = {
        "acknowledged_writes": 55,
        "acknowledged_vm_writes": 27,
        "acknowledged_writes_lost": 0,
        "planned_pause_responses": 113,
        "max_observed_ack_gap_seconds": 47.6,
        "scoped_sql_roles": False,
        "raw_client_token": "private-canary",
    }
    result = public_snapshot(value)["continuity"]
    assert result["acknowledged_writes_lost"] == 0 and result["planned_pause_responses"] == 113
    assert "private-canary" not in json.dumps(result)
    value["continuity"]["acknowledged_vm_writes"] = 56
    with pytest.raises(ValueError):
        public_snapshot(value)


def test_repeated_refresh_cannot_open_parallel_cloud_observations(web):
    active, release = Event(), Event()

    def slow():
        active.set()
        assert release.wait(3)
        return sample()

    web[1].side_effect = slow
    replies = []
    headers = {"Cookie": "sky_env_demo=" + "a" * 32}
    thread = Thread(target=lambda: replies.append(request(web, "/api/status", headers)[0]))
    thread.start()
    try:
        assert active.wait(1)
        assert request(web, "/api/status", headers)[0] == 429
        assert web[1].call_count == 1
    finally:
        release.set()
        thread.join(3)
    assert replies == [200]
    assert request(web, "/api/status", headers)[0] == 200
