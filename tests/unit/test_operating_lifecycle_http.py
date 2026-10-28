import json
import threading
from dataclasses import replace
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from unittest.mock import Mock
from uuid import uuid4

import pytest

from application.operating_lifecycle import OperatingLifecycle
from domain.access import LoginSource, Role
from interfaces.http.operating_lifecycle import handler_for_operating_lifecycle
from interfaces.http.shared_database import SharedDatabaseApp, handler_for_shared_database
from ports.deployment_reads import DeploymentSnapshot, OperatingLifecycleSnapshot
from tests.unit.test_deployment_writes import ID, Records, principal


@pytest.fixture
def web():
    records = Records()
    op = {
        "id": str(uuid4()),
        "kind": "db_dedicated_prepare",
        "status": "needs_attention",
        "attempt_id": str(uuid4()),
        "row_version": 8,
        "external_pending": True,
        "stage": "target_outcome_uncertain",
        "created_at": "2026-10-28T00:00:00Z",
    }
    actor = replace(principal(role=Role.ADMIN), login_source=LoginSource.EXTERNAL_IDP)
    identities = {
        "admin": actor,
        "viewer": replace(actor, role=Role.VIEWER),
        "foreign": replace(actor, organization_id="other"),
    }
    app = SharedDatabaseApp(
        Mock(),
        Mock(check_ready=Mock()),
        authenticator=Mock(authenticate_request=lambda h: identities.get(h.get("Authorization"))),
        origin="http://127.0.0.1",
    )
    reads = Mock(
        lifecycle=lambda *_: OperatingLifecycleSnapshot(DeploymentSnapshot(records.job, [], 1), (op,), False)
    )
    recovery = Mock(resume=Mock(return_value={"status": "queued", "data_routing_changed": False}))
    service = OperatingLifecycle(reads, recovery=recovery)
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        handler_for_operating_lifecycle(app, service, base_handler=handler_for_shared_database(app)),
    )
    app.origin = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def request(path=None, body=None, headers=None):
        c = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        try:
            c.request(
                "POST" if body is not None else "GET",
                path or f"/api/jobs/{ID}/operating-lifecycle",
                json.dumps(body) if body is not None else None,
                {
                    "Authorization": "admin",
                    "Origin": app.origin,
                    "Content-Type": "application/json",
                    **(headers or {}),
                },
            )
            r = c.getresponse()
            raw = r.read()
            return (
                r.status,
                raw.decode() if r.getheader("Content-Type", "").startswith("text/html") else json.loads(raw),
                dict(r.getheaders()),
            )
        finally:
            c.close()

    yield request, op, recovery
    server.shutdown()
    server.server_close()
    thread.join(5)


def test_owned_status_and_page_do_not_execute_recovery(web):
    request, _, recovery = web
    assert request()[1]["phase"] == "needs_attention"
    status, page, headers = request("/operations?job=" + ID)
    assert status == 200 and "Blue → Green" in page and headers["Cache-Control"] == "no-store"
    assert request(headers={"Authorization": "viewer"})[1]["operations"][0]["recovery_enabled"] is False
    recovery.resume.assert_not_called()


@pytest.mark.parametrize(
    "headers,status",
    [
        ({"Authorization": "foreign"}, 404),
        ({"Authorization": "invalid"}, 403),
        ({"Authorization": "viewer"}, 403),
        ({"Origin": "https://other.example"}, 403),
    ],
)
def test_resume_checks_identity_owner_and_origin(web, headers, status):
    request, op, recovery = web
    code, _, _ = request(
        f"/api/jobs/{ID}/operations/{op['id']}/resume-preparation",
        {"attempt_id": op["attempt_id"], "row_version": 8, "confirm_reconciliation": True},
        headers,
    )
    assert code == status
    recovery.resume.assert_not_called()


def test_exact_snapshot_resume_only_and_no_browser_runtime_injection(web):
    request, op, recovery = web
    path = f"/api/jobs/{ID}/operations/{op['id']}/resume-preparation"
    body = {"attempt_id": op["attempt_id"], "row_version": 8, "confirm_reconciliation": True}
    assert request(path, {**body, "target": "untrusted"})[0] == 400
    assert request(path, {**body, "row_version": 7})[0] == 409
    assert request(path, body)[0] == 202
    recovery.resume.assert_called_once()
