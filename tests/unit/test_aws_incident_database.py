"""AWS registration resolution performs reads only and never adopts a database."""

from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from ports.shared_database import PoolAllocationError

pytest_plugins = ["tests.unit.test_aws_shared_database"]


def state(adapter):
    return SimpleNamespace(
        region=adapter.settings.pool.region,
        host="state.example",
        database="sky_state",
        secret_arn=f"arn:aws:secretsmanager:{adapter.settings.pool.region}:{adapter.settings.pool.account_id}:secret:state-test01",
    )


def resolve(adapter, request, settings=None):
    return adapter.incident_restriction(
        request.binding(),
        settings or state(adapter),
        guard=Mock(),
        connection_guard=Mock(),
    )


def test_ready_allocation_resolves_without_app_secret_reads_or_creates(aws):
    adapter, request, clients, _, _, _, connect = aws
    allocator = Mock()
    allocator.existing_allocation.return_value = request
    with patch.object(adapter, "_allocator", return_value=allocator):
        restriction = resolve(adapter, request)
    assert restriction.binding == request.binding()
    assert restriction.fence.role == request.login_role
    assert restriction.fence.administrative_database == request.pool.control_database
    allocator.existing_allocation.assert_called_once_with(request.binding())
    clients["secretsmanager"].create_secret.assert_not_called()
    calls = clients["secretsmanager"].get_secret_value.call_args_list
    assert len(calls) == 1 and calls[0].kwargs["SecretId"] == adapter.settings.admin_secret_arn
    connect.assert_not_called()  # SQL adapter is replaced only in this unit test.


@pytest.mark.parametrize(
    "change", ["account", "region", "database", "secret", "endpoint", "binding", "unregistered"]
)
def test_mismatch_refused_without_any_mutation(aws, change):
    adapter, request, clients, _, instance, _, connect = aws
    settings = state(adapter)
    allocator = Mock()
    allocator.existing_allocation.return_value = request
    if change == "account":
        settings.secret_arn = settings.secret_arn.replace("111111111111", "222222222222")
    elif change == "region":
        settings.region = "us-east-1"
    elif change == "database":
        settings.database = request.pool.control_database
    elif change == "secret":
        settings.secret_arn = adapter.settings.admin_secret_arn
    elif change == "endpoint":
        settings.host = instance["Endpoint"]["Address"].upper() + "."
    elif change == "binding":
        request = replace(request, pool=replace(request.pool, instance_id="other-pool"))
    else:
        allocator.existing_allocation.side_effect = PoolAllocationError("Unregistered")
    with patch.object(adapter, "_allocator", return_value=allocator), pytest.raises(PoolAllocationError):
        resolve(adapter, request, settings)
    clients["secretsmanager"].create_secret.assert_not_called()
    clients["secretsmanager"].put_secret_value.assert_not_called()
    connect.assert_not_called()


def test_each_fence_connection_rechecks_admin_and_allocation(aws):
    adapter, request, *_ = aws
    allocator = Mock()
    allocator.existing_allocation.return_value = request
    membership = Mock()
    with patch.object(adapter, "_allocator", return_value=allocator):
        restriction = adapter.incident_restriction(
            request.binding(),
            state(adapter),
            guard=Mock(),
            connection_guard=membership,
        )
    with patch.object(adapter, "_connection", return_value="connection"):
        assert restriction.fence.connect() == "connection"
    assert allocator.existing_allocation.call_count == 2
    assert membership.call_count == 2
    membership.side_effect = PermissionError("revoked")
    with patch.object(adapter, "_connection") as connect, pytest.raises(PermissionError):
        restriction.fence.connect()
    connect.assert_not_called()


def test_incident_resolution_uses_the_real_allocator_composition(aws):
    """Do not replace _allocator: its endpoint tuple contract must be exercised."""
    adapter, request, clients, _, _, _, connect = aws
    with patch(
        "adapters.database.shared_pool.PostgresSharedPool.existing_allocation", return_value=request
    ) as lookup:
        restriction = resolve(adapter, request)
    assert restriction.binding == request.binding()
    lookup.assert_called_once_with(request.binding())
    connect.assert_not_called()
    clients["secretsmanager"].create_secret.assert_not_called()
