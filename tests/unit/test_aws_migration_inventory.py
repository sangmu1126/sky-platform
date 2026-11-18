"""Registered AWS auditors are inspected, never invoked in provisioning mode."""

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from unittest.mock import Mock, patch

import pytest

from adapters.aws.migration_inventory import AwsDedicatedInventoryVerifier, AwsSharedInventoryVerifier
from domain.database_inventory import DatabaseInventoryUnavailable
from domain.database_migration import DatabaseLocation, DatabasePlacement
from tests.unit.test_aws_dedicated_database import prepared as prepared  # noqa: PLC0414 -- pytest fixture re-export
from tests.unit.test_aws_shared_database import aws as aws  # noqa: PLC0414 -- pytest fixture re-export


def placement(binding):
    return DatabasePlacement(
        binding.organization_id,
        binding.application_id,
        binding.role,
        DatabaseLocation("aws", "rds_postgresql", binding.account_id, binding.region),
        binding.instance_id,
        binding.database_name,
        binding.owner_ref,
        17,
    )


def clock():
    return datetime.now(UTC)


def test_shared_verifier_reuses_existing_allocation_auditor_without_mutation(aws):
    allocator, request, _, _, instance, _, _ = aws
    endpoint = placement(request.binding())
    receipt = {
        "binding": request.binding().__dict__,
        "resource_id": allocator.settings.resource_id,
        "host": instance["Endpoint"]["Address"],
        "port": 5432,
        "tls_verified": True,
        "cross_database_access_denied": True,
    }
    with (
        patch.object(allocator, "inspect_allocation", return_value=receipt) as inspect,
        patch.object(allocator, "allocate") as allocate,
    ):
        proof = AwsSharedInventoryVerifier(allocator, endpoint, clock=clock).verify(endpoint)
    inspect.assert_called_once_with(request.binding())
    allocate.assert_not_called()
    assert proof.placement == endpoint and proof.server_port == 5432


def test_shared_registration_cannot_adopt_another_account_or_database(aws):
    allocator, request, *_ = aws
    endpoint = placement(request.binding())
    with pytest.raises(ValueError):
        AwsSharedInventoryVerifier(
            allocator,
            replace(endpoint, location=replace(endpoint.location, authority_ref="222222222222")),
            clock=clock,
        )
    verifier = AwsSharedInventoryVerifier(allocator, endpoint, clock=clock)
    with patch.object(allocator, "inspect_allocation") as inspect:
        with pytest.raises(ValueError):
            verifier.verify(replace(endpoint, database_name="foreign"))
        inspect.assert_not_called()


def test_shared_provider_diagnostics_are_not_exposed(aws):
    allocator, request, *_ = aws
    endpoint = placement(request.binding())
    with (
        patch.object(allocator, "inspect_allocation", side_effect=RuntimeError("password=CANARY")),
        pytest.raises(DatabaseInventoryUnavailable) as exc,
    ):
        AwsSharedInventoryVerifier(allocator, endpoint, clock=clock).verify(endpoint)
    assert "CANARY" not in str(exc.value)


def test_dedicated_verifier_uses_existing_identity_tags_network_and_tls_gates(prepared):
    adapter, plan, operation, clients, instance, _ = prepared
    from domain.database import DatabaseBinding

    endpoint = placement(DatabaseBinding(**plan["target"]))
    adapter._verify_tls = Mock()
    adapter.prepare = Mock()
    verifier = AwsDedicatedInventoryVerifier(
        adapter,
        endpoint,
        plan,
        operation,
        resource_id=instance["DbiResourceId"],
        clock=clock,
        guard=lambda: None,
    )
    proof = verifier.verify(endpoint)
    assert proof.server_hostname == instance["Endpoint"]["Address"]
    adapter._verify_tls.assert_called_once()
    adapter.prepare.assert_not_called()
    clients["rds"].create_db_instance.assert_not_called()


@pytest.mark.parametrize("change", ["resource_id", "tags", "public"])
def test_dedicated_instance_replacement_or_ownership_drift_is_denied(prepared, change):
    adapter, plan, operation, clients, instance, _ = prepared
    from domain.database import DatabaseBinding

    endpoint = placement(DatabaseBinding(**plan["target"]))
    verifier = AwsDedicatedInventoryVerifier(
        adapter,
        endpoint,
        deepcopy(plan),
        operation,
        resource_id=instance["DbiResourceId"],
        clock=clock,
        guard=lambda: None,
    )
    if change == "resource_id":
        instance["DbiResourceId"] = "db-REPLACEMENT"
    elif change == "tags":
        clients["rds"].list_tags_for_resource.return_value["TagList"] = []
    else:
        instance["PubliclyAccessible"] = True
    adapter._verify_tls = Mock()
    with pytest.raises(DatabaseInventoryUnavailable):
        verifier.verify(endpoint)
    adapter._verify_tls.assert_not_called()
    clients["rds"].create_db_instance.assert_not_called()
