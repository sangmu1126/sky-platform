"""ECS metadata is trusted only at the fixed endpoint and registered scope."""

import json
from dataclasses import replace
from unittest.mock import MagicMock, Mock, patch

import pytest

from adapters.aws.preparation_executor import load_preparation_executor_identity
from ports.preparation_executor import EcsPreparationExecutor, validate_preparation_executor

ARN = "arn:aws:ecs:ap-northeast-2:111111111111:task/sky-worker/" + "a" * 32
URI = "http://169.254.170.2/v4/test-task"
SCOPE = {"account_id": "111111111111", "region": "ap-northeast-2"}


def test_local_identity_does_not_access_metadata():
    with patch("urllib.request.build_opener", side_effect=AssertionError("Network")):
        assert load_preparation_executor_identity(None, **SCOPE) is None


@pytest.mark.parametrize(
    "uri",
    ["", "http://evil.example/v4/task", "https://169.254.170.2/v4/task", URI + "?x=1", URI + "/../task"],
)
def test_invalid_metadata_endpoint_is_rejected_before_network(uri):
    with (
        patch("urllib.request.build_opener", side_effect=AssertionError("Network")),
        pytest.raises(ValueError),
    ):
        load_preparation_executor_identity(uri, **SCOPE)


@pytest.mark.parametrize(
    "change", [None, "account", "region", "short_arn", "oversize", "missing", "http", "unavailable"]
)
def test_metadata_requires_bounded_successful_task_identity(change):
    response = MagicMock(status=200)
    response.__enter__.return_value = response
    arn = ARN
    if change == "account":
        arn = ARN.replace("111111111111", "222222222222")
    elif change == "region":
        arn = ARN.replace("ap-northeast-2", "us-east-1")
    elif change == "short_arn":
        arn = ARN.replace("sky-worker/", "")
    response.read.return_value = json.dumps({"TaskARN": arn}).encode()
    if change == "oversize":
        response.read.return_value = b"x" * 16385
    elif change == "missing":
        response.read.return_value = b"{}"
    elif change == "http":
        response.status = 503
    opener = Mock()
    opener.open.return_value = response
    if change == "unavailable":
        opener.open.side_effect = OSError("Connection refused")
    with patch("urllib.request.build_opener", return_value=opener) as build:
        if change:
            with pytest.raises(OSError, match="identity unavailable"):
                load_preparation_executor_identity(URI, **SCOPE)
        else:
            assert load_preparation_executor_identity(URI, **SCOPE) == EcsPreparationExecutor(ARN)
            opener.open.assert_called_once_with(URI + "/task", timeout=5)
            assert build.call_args.args[0].proxies == {}
            assert build.call_args.args[1].redirect_request(None, None, 302, "", {}, "http://evil") is None
            response.read.assert_called_once_with(16385)


def test_worker_records_executor_before_preparing_and_strips_no_provenance(flow):
    worker, _, _, operations, preparer, operation, receipt, _ = flow
    worker.executor = EcsPreparationExecutor(ARN)

    def prepare(_plan, *, operation_id, guard):
        guard()
        assert operations.begin_external.call_args.args[1]["executor"] == {
            "kind": "ecs_task",
            "task_arn": ARN,
            "worker_owner": worker.owner,
            "attempt_id": operation.attempt_id,
        }
        return receipt

    preparer.prepare.side_effect = prepare
    assert worker.execute(operation.id, operation.attempt_id)["status"] == "succeeded"


def test_replacement_worker_preserves_original_executor_on_receipt_resume(flow):
    worker, _, _, operations, preparer, operation, receipt, _ = flow
    from application.database_promotion_workflow import preparation_intent

    original = EcsPreparationExecutor(ARN).record("old-worker", operation.attempt_id)
    operations.get.return_value = replace(
        operation,
        external_intent=preparation_intent(operation.command["proposal"]["plan"], operation.id, original),
        external_receipt=receipt,
        checkpoint={"stage": "target_prepared"},
    )
    worker.executor = EcsPreparationExecutor(ARN.replace("a" * 32, "b" * 32))
    assert worker.execute(operation.id, operation.attempt_id)["status"] == "succeeded"
    preparer.prepare.assert_not_called()
    operations.begin_external.assert_not_called()


@pytest.mark.parametrize("change", ["kind", "extra", "attempt", "owner", "task"])
def test_executor_record_rejects_unbounded_or_unrecognized_fields(flow, change):
    record = EcsPreparationExecutor(ARN).record("worker", flow[5].attempt_id)
    if change == "extra":
        record["credentials"] = "must-not-persist"
    else:
        field, value = {
            "kind": ("kind", "user-supplied"),
            "attempt": ("attempt_id", "not-a-uuid"),
            "owner": ("worker_owner", "x" * 129),
            "task": ("task_arn", "arbitrary-host"),
        }[change]
        record[field] = value
    with pytest.raises(ValueError):
        validate_preparation_executor(record)


def test_other_account_executor_cannot_be_bound_to_preparation(flow):
    from application.database_promotion_workflow import preparation_intent

    operation = flow[5]
    record = EcsPreparationExecutor(ARN.replace("111111111111", "222222222222")).record(
        "worker", operation.attempt_id
    )
    with pytest.raises(ValueError, match="account and region"):
        preparation_intent(operation.command["proposal"]["plan"], operation.id, record)


pytest_plugins = ["tests.unit.test_database_promotion_workflow"]
