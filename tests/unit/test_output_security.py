"""One synthetic secret must not reach model context, stored events or HTTP JSON."""

import base64
import json
from http.server import ThreadingHTTPServer
from threading import Thread
from unittest.mock import Mock
from urllib.request import urlopen

import pytest

from application.output_security import public_value, redact


@pytest.mark.parametrize(
    "secret",
    [
        "sk-LOCAL_SYNTHETIC_SECRET_CANARY_123456789",
        "postgresql://user:synthetic-pass@db.invalid/sky",
        "Bearer synthetic-bearer-canary",
        "Basic c3ludGhldGljOmNhbmFyeQ==",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.c3ludGhldGlj",
        "https://example.invalid/?access_token=synthetic-canary&safe=1",
    ],
)
def test_credential_patterns_are_redacted_without_registered_values(secret):
    assert redact(secret) != secret


def test_registered_runtime_secret_encoded_forms_are_not_exported(monkeypatch):
    value = "opaque-canary/+with space-123456"
    monkeypatch.setenv("AWS_SESSION_TOKEN", value)
    from urllib.parse import quote

    for encoded in (value, quote(value, safe=""), base64.b64encode(value.encode()).decode()):
        assert encoded not in redact("failure " + encoded)
    assert public_value({"count": 2, "enabled": True, "secret_ref": "arn:aws:secretsmanager:x"}) == {
        "count": 2,
        "enabled": True,
        "secret_ref": "arn:aws:secretsmanager:x",
    }


def test_model_context_and_persisted_event_use_same_boundary(tmp_path, monkeypatch):
    import threading

    from application.analysis import source_context
    from interfaces.http.server import App

    canary = "opaque-local-test-credential-123456"
    monkeypatch.setenv("OPENAI_API_KEY", canary)
    (tmp_path / "app.py").write_text("message = " + repr(canary))
    assert canary not in json.dumps(source_context(tmp_path))
    app = object.__new__(App)
    app.lock = threading.RLock()
    app.jobs = {"test": {"events": []}}
    app.save = Mock()
    app.event("test", "error", "provider failed " + canary)
    assert canary not in json.dumps(app.jobs)
    app.save.assert_called_once_with("test")


def test_real_http_response_does_not_expose_nested_error_canary(monkeypatch):
    from interfaces.http.deployment_reads import DatabaseReadApp, handler_for_reads

    canary = "opaque-http-canary-123456"
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", canary)
    app = DatabaseReadApp(Mock())
    handler = handler_for_reads(app)

    class Probe(handler):
        def do_GET(self):
            self.json_response(400, {"error": {"details": ["provider " + canary]}, "attempt": 2})

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Probe)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        from urllib.error import HTTPError

        with pytest.raises(HTTPError) as e:
            urlopen("http://127.0.0.1:" + str(server.server_port), timeout=5)
        body = e.value.read()
        assert canary.encode() not in body
        assert json.loads(body)["attempt"] == 2
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_provider_failure_is_redacted_before_health_history_persistence(tmp_path, monkeypatch):
    from unittest.mock import patch

    from interfaces.http.server import App

    canary = "opaque-health-provider-canary-20261030"
    monkeypatch.setenv("AWS_SESSION_TOKEN", canary)
    app = App(tmp_path)
    job = "a" * 16
    app.jobs[job] = {
        "id": job,
        "status": "succeeded",
        "target": "local-docker",
        "plan": {"health_path": "/"},
        "result": {
            "container": "sky-" + job + "-a1",
            "image": "sky/test:latest",
            "url": "http://127.0.0.1:49152",
        },
    }
    with patch(
        "application.health.subprocess.run", side_effect=OSError("synthetic provider failure " + canary)
    ):
        result = app.check_and_record_health(job, "manual")
    assert result["healthy"] is False and canary not in result["reason"]
    assert canary not in json.dumps(app.health_history)
    assert all(canary not in path.read_text() for path in tmp_path.rglob("*.json"))


def test_health_storage_failure_does_not_keep_raw_provider_credentials(tmp_path, monkeypatch):
    from unittest.mock import patch

    from interfaces.http.server import App

    canary = "opaque-health-store-canary-20261030"
    monkeypatch.setenv("PGPASSWORD", canary)
    app = App(tmp_path)
    job = "b" * 16
    app.jobs[job] = {
        "id": job,
        "status": "succeeded",
        "target": "local-docker",
        "result": {"url": "http://127.0.0.1:49152"},
    }
    with (
        patch(
            "application.monitoring.check_deployment", return_value={"healthy": True, "reason": "HTTP 200"}
        ),
        patch.object(app.record_store, "save_health", side_effect=OSError(canary)),
    ):
        app.check_and_record_health(job, "manual")
    assert canary not in app.monitor_errors[job] and "[REDACTED]" in app.monitor_errors[job]
