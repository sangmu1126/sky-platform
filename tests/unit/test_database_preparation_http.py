"""Authenticated HTTP intake and status; cloud provisioning is never performed here."""

import json
import threading
from contextlib import contextmanager
from dataclasses import replace
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest

from application.database_promotion_workflow import PromotionPreparationAdmission
from domain.access import LoginSource, Role
from interfaces.database_preparation import DatabasePreparationController, load_preparation_api_configuration
from interfaces.http.database_cutover import handler_for_database_cutover
from interfaces.http.database_preparation import handler_for_database_preparation
from interfaces.http.shared_database import SharedDatabaseApp
from interfaces.operating_review import OperatingReviewController
from ports.operations import Operation
from tests.unit.test_deployment_writes import principal
from tests.unit.test_operating_review import ID, NOW

pytest_plugins = ["tests.unit.test_dedicated_database_admission"]


@contextmanager
def serve_preparation(records, operations, policies, pool):
    actor = replace(principal(), login_source=LoginSource.EXTERNAL_IDP)
    identities = {
        "deployer": actor,
        "viewer": replace(actor, role=Role.VIEWER),
        "foreign": replace(actor, organization_id="foreign"),
    }
    app = SharedDatabaseApp(
        Mock(),
        Mock(),
        authenticator=Mock(authenticate_request=lambda h: identities.get(h.get("Authorization"))),
        origin="http://127.0.0.1",
    )
    reviews = OperatingReviewController(records, policies, clock=lambda: NOW)
    admission = PromotionPreparationAdmission(records, operations, policies, enabled=True, clock=lambda: NOW)
    controller = DatabasePreparationController(reviews, admission, pool)
    handler = handler_for_database_preparation(app, reviews, controller)
    # Mirror the production stack: cutover wraps preparation, which wraps reviews.
    handler = handler_for_database_cutover(
        app, reviews, Mock(detail=Mock(return_value={"scope": "cutover"})), base_handler=handler
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    app.origin = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def request(*, body=None, method="POST", suffix="", path=None, headers=None):
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        values = {"Authorization": "deployer", "Origin": app.origin, "Content-Type": "application/json"}
        values.update(headers or {})
        try:
            connection.request(
                method, path or f"/api/jobs/{ID}/database-preparation{suffix}", json.dumps(body or {}), values
            )
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    try:
        yield request, controller
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


@pytest.fixture
def web(admission_setup, registered):
    records, policy, approved = admission_setup
    operations = Mock()
    operation = Operation(
        str(uuid4()),
        "game",
        "db_dedicated_prepare",
        "queued",
        str(uuid4()),
        {},
        {},
        None,
        False,
        1,
        None,
        None,
    )

    def admit(_app, _kind, _key, command):
        saved = replace(operation, command=command)
        operations.get.return_value = saved
        return saved

    operations.admit.side_effect = admit
    body = {"proposal_id": approved["proposal_id"], "request_key": "click-one", "confirm_preparation": True}
    with serve_preparation(records, operations, {ID: policy}, registered[0].source.pool) as (
        request,
        controller,
    ):
        yield request, controller, records, operations, body, operation


def test_explicit_request_returns_202_and_owned_status_without_cloud_calls(web):
    request, _, _, operations, body, operation = web
    with patch("boto3.client", side_effect=AssertionError("Cloud access")):
        status, receipt = request(body=body)
        assert status == 202 and receipt["operation_id"] == operation.id and receipt["status"] == "queued"
        assert (
            receipt["scope"] == "dedicated_target_preparation_only"
            and receipt["data_routing_changed"] is False
        )
        assert (
            request(method="GET", suffix="/" + operation.id, headers={"Authorization": "viewer"})[1]
            == receipt
        )
        assert request(method="GET")[1]["automatic_execution"] is False
    assert operations.admit.call_args.args[1] == "db_dedicated_prepare"
    assert operations.admit.call_args.args[2].startswith("prepare-")
    assert request(method="GET", path=f"/api/jobs/{ID}/operating-review")[1]["execution_enabled"] is False
    assert request(method="GET", path=f"/api/jobs/{ID}/database-cutover")[1] == {"scope": "cutover"}


@pytest.mark.parametrize(
    "headers,status",
    [
        ({"Authorization": "viewer"}, 403),
        ({"Authorization": "foreign"}, 404),
        ({"Authorization": "invalid"}, 403),
        ({"Origin": "https://foreign.example"}, 403),
    ],
)
def test_identity_owner_and_origin_are_required(web, headers, status):
    request, _, _, operations, body, _ = web
    assert request(body=body, headers=headers)[0] == status
    operations.admit.assert_not_called()


@pytest.mark.parametrize("change", ["implicit", "target", "secret", "policy", "actor", "bad_key"])
def test_browser_cannot_override_registration_or_omit_consent(web, change):
    request, _, _, operations, body, _ = web
    body = dict(body)
    if change == "implicit":
        body["confirm_preparation"] = 1
    elif change == "bad_key":
        body["request_key"] = "../unsafe"
    else:
        body[change] = "untrusted"
    assert request(body=body)[0] == 400
    operations.admit.assert_not_called()


@pytest.mark.parametrize("change", ["disabled", "unapproved", "foreign_pool", "expired"])
def test_stale_or_disabled_preparation_never_admits(web, change):
    request, controller, records, operations, body, _ = web
    if change == "disabled":
        controller.admission.enabled = False
    elif change == "unapproved":
        records.job["operating_proposal"]["status"] = "pending_approval"
    elif change == "foreign_pool":
        records.job["workload_database_binding"]["instance_id"] = "foreign"
    else:
        controller.admission.clock = lambda: "2026-10-12T00:00:00+00:00"
    assert request(body=body)[0] == 409
    operations.admit.assert_not_called()


@pytest.mark.parametrize("change", ["job", "organization", "kind", "application"])
def test_status_cannot_disclose_foreign_operation(web, change):
    request, _, _, operations, body, operation = web
    assert request(body=body)[0] == 202
    stored = operations.get.return_value
    if change == "job":
        stored = replace(stored, command={**stored.command, "job_id": "f" * 16})
    elif change == "organization":
        stored = replace(stored, command={**stored.command, "requested_by": {"organization_id": "other"}})
    elif change == "kind":
        stored = replace(stored, kind="deploy")
    else:
        stored = replace(stored, application_id="other")
    operations.get.return_value = stored
    assert request(method="GET", suffix="/" + operation.id)[0] == 404


def test_preparation_idempotency_key_is_scoped_to_authenticated_actor(web):
    request, controller, _, operations, body, _ = web
    request(body=body)
    first = operations.admit.call_args.args[2]
    actor = replace(principal(), user_id="user2")
    controller.submit(actor, ID, proposal_id=body["proposal_id"], request_key=body["request_key"])
    assert operations.admit.call_args.args[2] != first


def test_preparation_configuration_requires_explicit_opt_in_and_separate_queue(
    admission_setup, registered, monkeypatch
):
    _, policy, _ = admission_setup
    source = registered[0].source
    monkeypatch.delenv("SKY_DEDICATED_PREPARATION_ENABLED", raising=False)
    assert load_preparation_api_configuration(policies={ID: policy}, source=source) is None
    monkeypatch.setenv("SKY_DEDICATED_PREPARATION_ENABLED", "true")
    with patch("boto3.client", side_effect=AssertionError("Cloud access")):
        assert load_preparation_api_configuration(policies={ID: policy}, source=source) == registered[0]
    monkeypatch.setenv(
        "SKY_DATABASE_CUTOVER_QUEUE_URL",
        "https://sqs.ap-northeast-2.amazonaws.com/111111111111/dedicated.fifo",
    )
    with pytest.raises(ValueError, match="separate"):
        load_preparation_api_configuration(policies={ID: policy}, source=source)


@pytest.mark.parametrize(
    "change", ["flag", "missing_registration", "digest", "missing_policies", "cost", "foreign_queue"]
)
def test_invalid_preparation_configuration_rejected_offline(admission_setup, registered, monkeypatch, change):
    _, policy, _ = admission_setup
    policies = {ID: policy}
    monkeypatch.setenv("SKY_DEDICATED_PREPARATION_ENABLED", "true")
    if change == "flag":
        monkeypatch.setenv("SKY_DEDICATED_PREPARATION_ENABLED", "yes")
    elif change == "missing_registration":
        monkeypatch.delenv("SKY_DEDICATED_DATABASE_CONFIG_JSON")
    elif change == "digest":
        policies = {ID: replace(policy, target_configuration_digest="b" * 64)}
    elif change == "missing_policies":
        policies = None
    elif change == "cost":
        policies = {ID: replace(policy, cost_quote=None)}
    else:
        monkeypatch.setenv(
            "SKY_DEDICATED_DATABASE_QUEUE_URL",
            "https://sqs.ap-northeast-2.amazonaws.com/222222222222/foreign.fifo",
        )
    with patch("boto3.client", side_effect=AssertionError("Cloud access")), pytest.raises(ValueError):
        load_preparation_api_configuration(policies=policies, source=registered[0].source)


def test_enabled_intake_requires_hosted_shared_api(monkeypatch):
    from interfaces.b_runtime import main

    monkeypatch.setenv("SKY_DEDICATED_PREPARATION_ENABLED", "true")
    with pytest.raises(SystemExit) as error:
        main(["api", "--check-config"])
    assert error.value.code == 2


def test_hosted_api_opt_in_configuration_check_is_offline(admission_setup, monkeypatch, capsys):
    from argparse import Namespace

    from interfaces.shared_database_api import run_shared_database_api

    monkeypatch.setenv("SKY_DEDICATED_PREPARATION_ENABLED", "true")
    args = Namespace(
        auth_mode="alb",
        origin="https://sky.example",
        shared_database_pool_config=None,
        operating_review_policy_config=None,
        check_config=True,
    )
    parser = Mock(error=Mock(side_effect=AssertionError("Invalid configuration")))
    with (
        patch("interfaces.shared_database_api.load_hosted_identity", return_value=Mock()),
        patch(
            "interfaces.shared_database_api.RotatingDatabaseConnection", side_effect=AssertionError("DB call")
        ),
        patch("boto3.client", side_effect=AssertionError("Cloud call")),
    ):
        run_shared_database_api(args, parser)
    assert "no AWS/DB calls" in capsys.readouterr().out
