"""Provider identity is separate from TCP reachability and fails closed."""

import json
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta

import pytest

from adapters.runtime.provider_identity import (
    ObservedProviderResourceIdentity,
    ProviderIdentityEvidenceReader,
    ProviderIdentityInspectorRouter,
    RegisteredProviderIdentityInventory,
    RegisteredProviderResourceIdentity,
    assess_provider_identity,
    validate_provider_identity_report,
)
from adapters.runtime.workload_inventory import RegisteredLinuxDependencyProbe
from domain.workload_inventory import RegisteredDependencyPolicy, RegisteredWorkloadInventory
from ports.workload_inventory import WorkloadInventoryUnavailable
from tests.unit.test_environment_transition import NOW
from tests.unit.test_runtime_workload_inventory import runtime_case
from tests.unit.test_workload_inventory import registration


def provider_registration(inventory=None, *, endpoint="source"):
    inventory = inventory or registration()
    locations = {
        policy.logical_ref: (
            policy.source_location_ref if endpoint == "source" else policy.target_location_ref
        )
        for policy in inventory.dependency_policies
    }
    resources = []
    for policy in inventory.dependency_policies:
        if policy.category not in {"external_api", "object_store", "queue"}:
            continue
        resources.append(
            RegisteredProviderResourceIdentity(
                policy.logical_ref,
                policy.category,
                locations[policy.logical_ref],
                "partner" if policy.category == "external_api" else "aws",
                "https-service" if policy.category == "external_api" else "s3-bucket",
                policy.logical_ref + "-resource",
                ("1" if policy.category == "external_api" else "2") * 64,
                "provider-readonly-authority",
            )
        )
    return RegisteredProviderIdentityInventory(
        inventory,
        endpoint,
        "provider-readonly-authority",
        tuple(sorted(resources, key=lambda value: value.logical_ref)),
    )


def observation(resource, registration, **changes):
    value = ObservedProviderResourceIdentity(
        resource.logical_ref,
        resource.provider_ref,
        resource.resource_kind,
        resource.resource_ref,
        resource.identity_sha256,
        registration.authority_ref,
        NOW,
    )
    return replace(value, **changes)


def reader_case(registration):
    reports = {}

    class Inspector:
        def inspect(self, resource):
            return observation(resource, registration)

    class Publisher:
        def publish(self, report):
            reports[report["report_id"]] = report
            return report["report_id"]

    return (
        ProviderIdentityEvidenceReader(
            registration,
            Inspector(),
            Publisher(),
            clock=lambda: NOW,
        ),
        reports,
    )


def test_registered_provider_resources_are_durably_verified_without_execution_authority():
    registered = provider_registration()
    reader, reports = reader_case(registered)
    evidence = reader.collect(registered.inventory, "source")
    report = reports[evidence.report_id]
    assert report["status"] == "verified" and report["execution_authorized"] is False
    assert evidence.registration_id == registered.document()["provider_identity_registration_id"]
    assert {value["logical_ref"] for value in report["resources"]} == {
        "partner-api",
        "uploads",
    }
    assert validate_provider_identity_report(registered, report) == report


@pytest.mark.parametrize("change", ["identity", "authority", "stale", "missing"])
def test_provider_identity_mismatch_is_sanitized_and_persisted_blocked(change):
    registered = provider_registration()
    reader, reports = reader_case(registered)
    original = reader.inspector.inspect

    def inspect(resource):
        if change == "missing" and resource.logical_ref == "uploads":
            raise OSError("private provider failure")
        value = original(resource)
        if resource.logical_ref != "uploads":
            return value
        if change == "identity":
            return replace(value, identity_sha256="f" * 64)
        if change == "authority":
            return replace(value, authority_ref="other-authority")
        if change == "stale":
            return replace(value, observed_at=NOW - timedelta(seconds=31))
        return value

    reader.inspector.inspect = inspect
    with pytest.raises(WorkloadInventoryUnavailable):
        reader.collect(registered.inventory, "source")
    report = next(iter(reports.values()))
    assert report["status"] == "blocked"
    assert "provider_identity_unverified:uploads" in report["blockers"]
    assert "private provider failure" not in json.dumps(report)
    assert "f" * 64 not in json.dumps(report)


def test_provider_registration_is_exhaustive_and_report_tampering_is_rejected():
    registered = provider_registration()
    with pytest.raises(ValueError, match="Every provider dependency"):
        replace(registered, resources=registered.resources[:-1])
    report = assess_provider_identity(
        registered,
        tuple(observation(value, registered) for value in registered.resources),
        now=NOW,
    )
    tampered = deepcopy(report)
    tampered["resources"][0]["resource_ref"] = "other-resource"
    with pytest.raises(ValueError, match="Invalid provider identity report"):
        validate_provider_identity_report(registered, tampered)


def test_provider_inspector_router_requires_exact_registered_provider():
    aws = type("Inspector", (), {"inspect": lambda self, resource: resource.resource_ref})()
    https = type("Inspector", (), {"inspect": lambda self, resource: resource.resource_ref})()
    router = ProviderIdentityInspectorRouter((("aws", aws), ("https", https)))
    registered = provider_registration().resources[0]
    assert router.inspect(replace(registered, provider_ref="https")) == registered.resource_ref
    with pytest.raises(ValueError, match="inspector unavailable"):
        router.inspect(replace(registered, provider_ref="unknown"))


def provider_runtime_case(tmp_path):
    reader, source, proc, runtime_reports = runtime_case(tmp_path)
    provider_policy = RegisteredDependencyPolicy(
        "partner-api",
        "external_api",
        ("api",),
        "read",
        "partner-service",
        "partner-service",
        "retain",
    )
    inventory = RegisteredWorkloadInventory(
        source.inventory.inventory_ref,
        source.inventory.scope,
        source.inventory.component_roles,
        tuple(
            sorted(
                (*source.inventory.dependency_policies, provider_policy),
                key=lambda value: value.logical_ref,
            )
        ),
    )
    source = replace(source, inventory=inventory)
    provider = provider_registration(inventory)
    tcp = (proc / "101/net/tcp").read_text()
    tcp += " 5: 0100007F:9C40 0200007F:01BB 01 00000000:00000000 00:00000000 00000000 1000 0 102\n"
    (proc / "101/net/tcp").write_text(tcp)
    (proc / "101/fd/5").symlink_to("socket:[102]")
    runtime = replace(
        reader.registration,
        source=source,
        probes=tuple(
            sorted(
                (
                    *reader.registration.probes,
                    RegisteredLinuxDependencyProbe(
                        "partner-api", "api", "tcp", address="127.0.0.2", port=443
                    ),
                ),
                key=lambda value: (value.logical_ref, value.component_ref),
            )
        ),
        provider_identity_registration_id=provider.document()["provider_identity_registration_id"],
    )
    provider_reader, provider_reports = reader_case(provider)
    reader.registration = runtime
    reader.provider_identity_reader = provider_reader
    return reader, source, runtime_reports, provider_reports


def test_linux_runtime_requires_bound_provider_identity_in_addition_to_tcp(tmp_path):
    reader, source, runtime_reports, provider_reports = provider_runtime_case(tmp_path)
    snapshot = reader.collect(source.inventory, "source")
    assert len(snapshot.evidence_refs) == 2
    provider_ref = next(value for value in snapshot.evidence_refs if value.startswith("WPI-"))
    runtime_ref = next(value for value in snapshot.evidence_refs if value.startswith("WRI-"))
    assert provider_reports[provider_ref]["status"] == "verified"
    assert runtime_reports[runtime_ref]["provider_identity_report_id"] == provider_ref

    reader.provider_identity_reader = None
    with pytest.raises(WorkloadInventoryUnavailable):
        reader.collect(source.inventory, "source")
    blocked = list(runtime_reports.values())[-1]
    assert blocked["status"] == "blocked"
    assert "provider_identity_evidence_unavailable" in blocked["blockers"]
