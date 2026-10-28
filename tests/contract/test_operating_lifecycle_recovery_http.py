"""Real state DB/HTTP recovery; executor fence and target observations are controlled doubles."""

import json
import threading
from dataclasses import replace
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from unittest.mock import Mock

import pytest

from adapters.state.deployment_reads import PostgresDeploymentReads
from application.operating_lifecycle import OperatingLifecycle
from domain.access import LoginSource
from interfaces.http.operating_lifecycle import handler_for_operating_lifecycle
from interfaces.http.shared_database import SharedDatabaseApp, handler_for_shared_database
from tests.contract.test_operation_store import count
from tests.contract.test_operation_store import database as database  # noqa: PLC0414
from tests.contract.test_operation_store import store as store  # noqa: PLC0414
from tests.contract.test_preparation_recovery import recovery as recovery  # noqa: PLC0414
from tests.contract.test_preparation_revalidation import persisted as persisted  # noqa: PLC0414
from tests.contract.test_preparation_revalidation import preparation as preparation  # noqa: PLC0414

pytest_plugins = ["tests.unit.test_dedicated_database_admission"]


@pytest.mark.parametrize("lost_response", [False, True])
def test_http_reconciliation_keeps_same_operation_requeues_once_and_never_recreates_target(
    recovery, store, database, lost_response
):
    service, admin, blocked, _, observer, worker, preparer = recovery
    job_id = blocked.command["job_id"]
    actor = replace(admin, login_source=LoginSource.EXTERNAL_IDP)
    if lost_response:
        resume = service.resume

        def committed_then_lost(*args):
            resume(*args)
            raise OSError("Response lost after commit")

        service.resume = committed_then_lost
    app = SharedDatabaseApp(
        Mock(),
        Mock(check_ready=Mock()),
        authenticator=Mock(authenticate_request=lambda _: actor),
        origin="http://127.0.0.1",
    )
    lifecycle = OperatingLifecycle(
        PostgresDeploymentReads(database, workspace=store.workspace), recovery=service
    )
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        handler_for_operating_lifecycle(app, lifecycle, base_handler=handler_for_shared_database(app)),
    )
    app.origin = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def request(post=False):
        c = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        try:
            path = (
                f"/api/jobs/{job_id}/operations/{blocked.id}/resume-preparation"
                if post
                else f"/api/jobs/{job_id}/operating-lifecycle"
            )
            body = {
                "attempt_id": blocked.attempt_id,
                "row_version": blocked.row_version,
                "confirm_reconciliation": True,
            }
            c.request(
                "POST" if post else "GET",
                path,
                json.dumps(body) if post else None,
                {"Origin": app.origin, "Content-Type": "application/json"},
            )
            r = c.getresponse()
            return r.status, json.loads(r.read())
        finally:
            c.close()

    try:
        before = count(store, database, "outbox_events")
        assert request()[1]["phase"] == "needs_attention"
        assert count(store, database, "outbox_events") == before
        assert request(True)[0] == (503 if lost_response else 202)
        queued = store.get(blocked.id)
        assert queued.status == "queued" and queued.attempt_id != blocked.attempt_id
        assert request()[1]["phase"] == "executing"
        assert request(True)[0] == 409
        observer.observe.assert_called_once()
        assert (
            count(store, database, "operations") == 1
            and count(store, database, "outbox_events") == before + 1
        )
        assert worker.execute(queued.id, queued.attempt_id)["status"] == "succeeded"
        final = request()[1]
        assert final["operations"][0]["status"] == "succeeded"
        preparer.prepare.assert_called_once()  # original ambiguous provider request only
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)
