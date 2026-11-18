"""SQL metadata can verify only its explicit supplemental preservation criteria."""

from dataclasses import replace
from unittest.mock import patch

import pytest

from adapters.database.environment_preservation import (
    DATABASE_PRESERVATION_CRITERIA,
    DatabasePreservationCollector,
)
from application.database_migration_preflight import DatabaseMigrationPreflight
from domain.database_inventory import DatabaseInventoryUnavailable
from domain.environment_transition import BASELINE_CAPABILITIES, PreservationRequirement, TransitionScope
from engine.environment_transition import assess_environment_transition
from tests.unit.test_database_migration_preflight import NOW
from tests.unit.test_database_migration_preflight import case as case  # noqa: PLC0414 -- pytest fixture re-export


def bridge(case):
    source, target, policy, readers = case
    scope = TransitionScope("org", "app", "registered-aws", "registered-target", "a" * 64, "b" * 64, "c" * 64)
    collector = DatabasePreservationCollector(
        DatabaseMigrationPreflight(*readers, clock=lambda: NOW, max_age_seconds=60),
        source,
        target,
        policy,
        scope=scope,
        verifier_ref="registered-db-verifier",
    )
    return scope, collector


def test_collects_fresh_metadata_without_promoting_any_whole_environment_gate(case):
    scope, collector = bridge(case)
    observations = collector.collect(scope, DATABASE_PRESERVATION_CRITERIA)
    assert len(observations) == 4 and all(item.status == "verified" for item in observations)
    criteria = tuple(
        PreservationRequirement(key, "criterion-" + key, "d" * 64) for key in BASELINE_CAPABILITIES
    )
    result = assess_environment_transition(
        scope, (*criteria, *DATABASE_PRESERVATION_CRITERIA), observations, now=NOW
    )
    assert result["status"] == "blocked" and result["execution_authorized"] is False
    assert set(result["unresolved_capabilities"]) == set(BASELINE_CAPABILITIES)
    assert "server_hostname" not in str(result) and "db.example" not in str(result)
    for reader in case[3]:
        reader.inspect.assert_called_once()


def test_missing_inventory_is_unknown_not_claimed_data_loss_or_verified(case):
    scope, collector = bridge(case)
    case[3][1].inspect.side_effect = DatabaseInventoryUnavailable("private diagnostic")
    observations = collector.collect(scope, DATABASE_PRESERVATION_CRITERIA)
    assert len(observations) == 2 and {item.endpoint for item in observations} == {"source"}
    assert {item.requirement.capability: item.status for item in observations} == {
        "database_resource_ownership": "verified",
        "database_metadata_compatibility": "unknown",
    }


def test_schema_incompatibility_keeps_ownership_and_blocks_metadata(case):
    scope, collector = bridge(case)
    reader = case[3][1]
    reader.inspect.return_value = replace(reader.inspect.return_value, table_count=1)
    results = collector.collect(scope, DATABASE_PRESERVATION_CRITERIA)
    assert all(
        item.status == "failed"
        for item in results
        if item.requirement.capability == "database_metadata_compatibility"
    )
    assert all(
        item.status == "verified"
        for item in results
        if item.requirement.capability == "database_resource_ownership"
    )


def test_cannot_map_database_metadata_to_baseline_persistence_or_whole_environment_tls(case):
    scope, collector = bridge(case)
    for name in ("persistent_data", "transport_security", "backup_restore", "identity_access"):
        with pytest.raises(ValueError, match="cannot verify"):
            collector.collect(scope, (PreservationRequirement(name, "criterion", "d" * 64),))
    case[3][0].inspect.assert_not_called()


def test_changed_scope_or_criterion_revision_denies_collection(case):
    scope, collector = bridge(case)
    with pytest.raises(ValueError, match="scope changed"):
        collector.collect(replace(scope, source_revision="e" * 64), DATABASE_PRESERVATION_CRITERIA)
    with pytest.raises(ValueError, match="cannot verify"):
        collector.collect(scope, (replace(DATABASE_PRESERVATION_CRITERIA[0], criterion_revision="e" * 64),))
    case[3][0].inspect.assert_not_called()


def test_even_coherent_report_from_other_registered_database_cannot_be_rebound(case):
    scope, collector = bridge(case)
    original = collector.preflight.inspect
    other_source = replace(case[0], database_name="other_db")
    reader = case[3][0]
    reader.inspect.side_effect = lambda placement, plan_id: replace(
        reader.inspect.return_value,
        plan_id=plan_id,
        placement=placement,
        resource=replace(reader.inspect.return_value.resource, placement=placement),
    )
    case[3][1].inspect.side_effect = lambda placement, plan_id: replace(
        case[3][1].inspect.return_value, plan_id=plan_id
    )
    report = original(other_source, case[1], case[2], source_revision=scope.source_revision)
    with (
        patch.object(collector.preflight, "inspect", return_value=report),
        pytest.raises(ValueError, match="registration changed"),
    ):
        collector.collect(scope, DATABASE_PRESERVATION_CRITERIA)
