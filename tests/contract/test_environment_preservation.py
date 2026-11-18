"""Native VM/TLS SQL to environment review, with actual app ownership ledger.

Two DB instances on one disposable VM; no cross-environment migration claim.
Current membership is an explicit test policy, not a live identity integration.
"""

import os
from datetime import UTC, datetime

import pytest

pytest.importorskip("psycopg")

from adapters.database.environment_preservation import (
    DATABASE_PRESERVATION_CRITERIA,
    DatabasePreservationCollector,
)
from application.database_migration_preflight import DatabaseMigrationPreflight
from application.environment_transition import (
    EnvironmentTransitionReviewService,
    OperatorTransitionRegistry,
    RegisteredEnvironmentTransition,
    RegisteredPreservationCollector,
)
from domain.access import LoginSource, Principal, Role
from domain.database_migration import MigrationSafetyPolicy
from domain.environment_transition import BASELINE_CAPABILITIES, PreservationRequirement, TransitionScope
from tests.contract.test_database_migration_reviews import database as database  # noqa: PLC0414 -- pytest fixture re-export
from tests.contract.test_database_migration_reviews import store as store  # noqa: PLC0414 -- pytest fixture re-export
from tests.contract.test_migration_inventory import databases as databases  # noqa: PLC0414 -- pytest fixture re-export


@pytest.mark.parametrize("unsupported_view", [False, True])
def test_actual_registered_native_collection_is_narrow_and_never_authorizes_migration(
    databases, store, database, unsupported_view
):
    if not os.environ.get("SKY_TEST_VM_INVENTORY_REGISTRATION"):
        pytest.skip("Explicit native pinned-SSH registration required")
    placements, readers, connects = databases
    source, target = placements
    principal = Principal("alice", source.organization_id, Role.DEPLOYER, LoginSource.CORPORATE_SSO)
    with database() as db:
        db.execute(
            "INSERT INTO sky_state.application_owners(workspace,application_id,organization_id,created_by) VALUES(%s,%s,%s,%s)",
            (store.operations.workspace, source.application_id, source.organization_id, principal.user_id),
        )
    if unsupported_view:
        with connects[0]() as db:
            db.execute("CREATE VIEW score_view AS SELECT id FROM scores")
    scope = TransitionScope(
        source.organization_id,
        source.application_id,
        "registered-db-source",
        "registered-db-target",
        "a" * 64,
        "b" * 64,
        "c" * 64,
    )
    clock = lambda: datetime.now(UTC)
    collector = DatabasePreservationCollector(
        DatabaseMigrationPreflight(*readers, clock=clock, max_age_seconds=60),
        source,
        target,
        MigrationSafetyPolicy(120, 600, 86400),
        scope=scope,
        verifier_ref="native-db-reader",
    )
    requirements = (
        *(PreservationRequirement(key, "test-" + key, "d" * 64) for key in BASELINE_CAPABILITIES),
        *DATABASE_PRESERVATION_CRITERIA,
    )
    registration = RegisteredEnvironmentTransition(
        "native-review",
        scope,
        requirements,
        (RegisteredPreservationCollector("native-db-reader", DATABASE_PRESERVATION_CRITERIA, collector),),
    )
    service = EnvironmentTransitionReviewService(
        OperatorTransitionRegistry((registration,)),
        store,
        current_principal=lambda actor: actor if actor == principal else None,
        clock=clock,
    )
    result = service.review(principal, "native-review")
    checks = {check["capability"]: check["status"] for check in result["checks"]}
    assert checks["database_resource_ownership"] == "verified"
    assert checks["database_metadata_compatibility"] == ("failed" if unsupported_view else "verified")
    assert all(checks[key] == "unverified" for key in BASELINE_CAPABILITIES)
    assert result["status"] == "blocked" and not result["execution_authorized"]
    with connects[0]() as db:
        assert db.execute("SELECT * FROM scores ORDER BY id").fetchall() == [(1, 42), (2, 84)]
    with connects[1]() as db:
        assert db.execute("SELECT to_regclass('public.scores')").fetchone() == (None,)
