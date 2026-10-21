"""Real HTTP consent -> real PostgreSQL admission/outbox; no cloud SDK calls."""

from adapters.state.postgres import PostgresDeploymentRecordStore
from tests.contract.test_dedicated_database_admission import persisted as persisted  # noqa: PLC0414
from tests.contract.test_operation_store import count
from tests.contract.test_operation_store import database as database  # noqa: PLC0414
from tests.contract.test_operation_store import store as store  # noqa: PLC0414
from tests.unit.test_database_preparation_http import serve_preparation
from tests.unit.test_operating_review import ID

pytest_plugins = ["tests.unit.test_dedicated_database_admission"]


def test_authenticated_browser_admission_and_polling_are_durable(
    persisted, admission_setup, registered, store, database
):
    records = PostgresDeploymentRecordStore(database, workspace=store.workspace)
    body = {
        "proposal_id": persisted["proposal_id"],
        "request_key": "browser-one",
        "confirm_preparation": True,
    }
    with serve_preparation(records, store, {ID: admission_setup[1]}, registered[0].source.pool) as (
        request,
        _,
    ):
        status, receipt = request(body=body)
        assert status == 202 and receipt["status"] == "queued"
        assert request(body=body) == (status, receipt)
        assert request(
            method="GET", suffix="/" + receipt["operation_id"], headers={"Authorization": "viewer"}
        ) == (200, receipt)
        assert (
            request(method="GET", suffix="/" + receipt["operation_id"], headers={"Authorization": "foreign"})[
                0
            ]
            == 404
        )
    operation = store.get(receipt["operation_id"])
    assert operation.command["proposal"] == persisted
    assert operation.command["requested_by"] == {"user_id": "user1", "organization_id": "org1"}
    assert operation.external_intent is None and operation.status == "queued"
    assert [
        count(store, database, table) for table in ("operations", "mutation_scopes", "outbox_events")
    ] == [1, 1, 1]


def test_busy_application_returns_conflict_without_partial_admission(
    persisted, admission_setup, registered, store, database
):
    records = PostgresDeploymentRecordStore(database, workspace=store.workspace)
    store.admit("game", "deploy", "existing", {"source": "registered"})
    with serve_preparation(records, store, {ID: admission_setup[1]}, registered[0].source.pool) as (
        request,
        _,
    ):
        status, result = request(
            body={
                "proposal_id": persisted["proposal_id"],
                "request_key": "conflict",
                "confirm_preparation": True,
            }
        )
        assert status == 409 and "operation_id" not in result
    assert [
        count(store, database, table) for table in ("operations", "mutation_scopes", "outbox_events")
    ] == [1, 1, 1]
