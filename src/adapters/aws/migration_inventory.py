"""Bridge registered AWS ownership auditors into migration metadata collection.

Only existing-resource inspection is used. Never allocate a DB/secret, prepare
an RDS instance, edit networking or claim SQL connectivity proves AWS ownership.
"""

import hashlib
import json
import re
from copy import deepcopy
from dataclasses import asdict

from adapters.aws.dedicated_database import AwsDedicatedDatabasePreparer
from adapters.aws.shared_database import AwsSharedDatabaseAllocator
from domain.database import DatabaseBinding
from domain.database_inventory import DatabaseInventoryUnavailable, DatabaseResourceEvidence
from domain.database_migration import DatabasePlacement


def legacy_aws_binding(placement):
    if not isinstance(placement, DatabasePlacement) or placement.location.provider != "aws":
        raise ValueError("Explicit registered AWS placement required")
    return DatabaseBinding(
        placement.organization_id,
        placement.application_id,
        placement.role,
        placement.location.authority_ref,
        placement.location.location,
        placement.instance_id,
        placement.database_name,
        placement.owner_ref,
    )


def evidence(placement, receipt, host, port, clock):
    digest = hashlib.sha256(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return DatabaseResourceEvidence(placement, "AWS-" + digest, clock(), host, port)


class AwsSharedInventoryVerifier:
    def __init__(self, allocator, placement, *, clock):
        if not isinstance(allocator, AwsSharedDatabaseAllocator):
            raise TypeError("Registered AWS shared allocator required")
        binding = legacy_aws_binding(placement)
        pool = allocator.settings.pool
        if (binding.account_id, binding.region, binding.instance_id, binding.role) != (
            pool.account_id,
            pool.region,
            pool.instance_id,
            "shared_workload",
        ):
            raise ValueError("Inventory registration differs from workload pool")
        self.allocator, self.placement, self.binding, self.clock = allocator, placement, binding, clock

    def verify(self, placement):
        if placement != self.placement:
            raise ValueError("AWS inventory placement differs from registration")
        try:
            receipt = self.allocator.inspect_allocation(self.binding)
            if (
                receipt.get("binding") != asdict(self.binding)
                or receipt.get("resource_id") != self.allocator.settings.resource_id
                or receipt.get("tls_verified") is not True
                or receipt.get("cross_database_access_denied") is not True
            ):
                raise ValueError("Existing allocation identity changed")
            return evidence(placement, receipt, receipt["host"], receipt["port"], self.clock)
        except Exception:  # noqa: BLE001 -- AWS/SQL diagnostics can contain credentials
            raise DatabaseInventoryUnavailable("Registered AWS inventory ownership unavailable") from None


class AwsDedicatedInventoryVerifier:
    def __init__(self, preparer, placement, creation_plan, operation_id, *, resource_id, clock, guard):
        if not isinstance(preparer, AwsDedicatedDatabasePreparer):
            raise TypeError("Registered dedicated database auditor required")
        binding = legacy_aws_binding(placement)
        if binding.role != "dedicated_workload" or creation_plan.get("target") != asdict(binding):
            raise ValueError("Dedicated inventory registration differs from creation intent")
        if not isinstance(resource_id, str) or not re.fullmatch(r"db-[A-Za-z0-9]{1,64}", resource_id):
            raise ValueError("Pinned immutable dedicated resource ID required")
        self.preparer, self.placement, self.binding = preparer, placement, binding
        self.resource_id = resource_id
        self.plan, self.operation_id = deepcopy(creation_plan), operation_id
        self.clock, self.guard = clock, guard

    def verify(self, placement):
        if placement != self.placement:
            raise ValueError("AWS inventory placement differs from registration")
        try:
            p = self.preparer
            self.guard()
            target = p._preflight(self.plan, self.operation_id)
            if target != self.binding:
                raise ValueError("Dedicated registration changed")
            instance = p._describe(target.instance_id)
            if instance is None or instance.get("DbiResourceId") != self.resource_id:
                raise ValueError("Registered dedicated database is absent")
            p._verify(instance, target, p._target_tags(self.plan, self.operation_id, target), available=True)
            p._verify_tls(instance, target)
            self.guard()
            receipt = p._target_receipt(self.plan, self.operation_id, target, instance)
            return evidence(
                placement, receipt, instance["Endpoint"]["Address"], instance["Endpoint"]["Port"], self.clock
            )
        except Exception:  # noqa: BLE001 -- this read-only boundary must redact provider diagnostics
            raise DatabaseInventoryUnavailable("Registered AWS inventory ownership unavailable") from None
