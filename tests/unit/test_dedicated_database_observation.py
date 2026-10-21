"""Read-only recovery observations use SDK/SQL fixtures, never actual AWS."""

from unittest.mock import Mock
from uuid import uuid4

import pytest

from application.database_promotion_workflow import safe_target_receipt
from tests.unit.test_aws_shared_database import ServiceError

pytest_plugins = ["tests.unit.test_aws_dedicated_database"]


def assert_read_only(adapter, clients):
    assert {call[0] for call in clients["rds"].method_calls} <= {
        "describe_db_subnet_groups",
        "describe_db_parameters",
        "describe_db_instances",
        "list_tags_for_resource",
    }
    adapter.sleep.assert_not_called()


def test_observation_produces_only_verified_credential_free_target_receipt(prepared):
    adapter, plan, operation, clients, _, connection = prepared
    result = adapter.observe(plan, operation_id=operation, guard=Mock())
    assert safe_target_receipt(result, plan, operation) == result
    assert "fixture-secret" not in str(result)
    assert result["resource_id"] == "db-" + "A" * 26
    assert_read_only(adapter, clients)
    clients["rds"].describe_db_instances.assert_called_once()
    adapter.audit._connection.assert_called_once()
    query = connection.cursor.return_value.__enter__.return_value.execute.call_args.args[0]
    assert query.startswith("SELECT current_database()")


@pytest.mark.parametrize("change", ["absent", "creating", "denied", "foreign", "network", "tls"])
def test_unverified_target_never_creates_waits_or_reports_success(prepared, change):
    adapter, plan, operation, clients, instance, connection = prepared
    if change == "absent":
        clients["rds"].describe_db_instances.side_effect = ServiceError("DBInstanceNotFound")
    elif change == "creating":
        instance["DBInstanceStatus"] = "creating"
    elif change == "denied":
        clients["rds"].describe_db_instances.side_effect = ServiceError("AccessDenied")
    elif change == "foreign":
        operation = str(uuid4())
    elif change == "network":
        adapter.network._audit_network.side_effect = ValueError("Untrusted network")
    else:
        connection.cursor.return_value.__enter__.return_value.fetchone.return_value = (
            "game",
            "skyadmin",
            False,
        )
    with pytest.raises((ValueError, ServiceError)):
        adapter.observe(plan, operation_id=operation, guard=Mock())
    assert_read_only(adapter, clients)
    if change != "tls":
        adapter.audit._secret_value.assert_not_called()


@pytest.mark.parametrize("boundary", [1, 2, 3, 4, 5])
def test_recovery_guard_loss_blocks_later_reads_and_receipt(prepared, boundary):
    adapter, plan, operation, clients, _, _ = prepared
    guard = Mock(side_effect=[None] * (boundary - 1) + [OSError("Recovery authority lost")])
    with pytest.raises(OSError, match="authority lost"):
        adapter.observe(plan, operation_id=operation, guard=guard)
    assert guard.call_count == boundary
    assert_read_only(adapter, clients)
    if boundary <= 2:
        clients["rds"].describe_db_instances.assert_not_called()
    if boundary <= 3:
        clients["rds"].list_tags_for_resource.assert_not_called()
    if boundary <= 4:
        adapter.audit._secret_value.assert_not_called()
