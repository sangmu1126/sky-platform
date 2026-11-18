"""Actual PostgreSQL persistence for registered G1 inventory reports."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from unittest.mock import Mock
from uuid import uuid4

import pytest

from adapters.state.deployment_admission import PostgresDeploymentAdmission
from adapters.state.operations import PostgresOperationStore
from adapters.state.workload_inventory import PostgresWorkloadInventoryReports
from application.environment_dependency_inventory import (
    RegisteredDependencyInventoryCollector,
    dependency_inventory_requirement,
)
from domain.access import LoginSource, Principal, Role
from tests.contract.test_database_migration_reviews import database as database  # noqa: PLC0414
from tests.unit.test_environment_transition import NOW
from tests.unit.test_workload_inventory import registration, report, snapshot

ACTOR = Principal("alice", "org", Role.DEPLOYER, LoginSource.CORPORATE_SSO)


@pytest.fixture
def store(database):
    admission = PostgresDeploymentAdmission(
        PostgresOperationStore(database, workspace=uuid4().hex),
        account_id="111111111111",
        region="ap-northeast-2",
    )
    value = PostgresWorkloadInventoryReports(admission, current_principal=lambda principal: principal)
    value.initialize()
    with database() as db:
        db.execute(
            """INSERT INTO sky_state.application_owners
            (workspace,application_id,organization_id,created_by) VALUES(%s,'app','org','alice')""",
            (admission.operations.workspace,),
        )
    return value


def rows(store, database):
    with database() as db:
        return db.execute(
            "SELECT count(*) FROM sky_state.workload_inventory_reports WHERE workspace=%s",
            (store.operations.workspace,),
        ).fetchone()[0]


def test_report_is_idempotent_survives_restart_and_creates_no_operation(store, database):
    registered = registration()
    document = report(registered)
    identity = store.record(ACTOR, registered, document)
    assert store.record(ACTOR, registered, document) == identity
    restarted = PostgresWorkloadInventoryReports(
        store.admission, current_principal=lambda principal: principal
    )
    assert restarted.read(ACTOR, registered, identity) == document
    restarted.check_ready()
    with database() as db:
        assert rows(store, database) == 1
        assert db.execute(
            "SELECT count(*) FROM sky_state.operations WHERE workspace=%s",
            (store.operations.workspace,),
        ).fetchone() == (0,)


def test_concurrent_publish_is_one_report_and_foreign_membership_is_denied(store, database):
    registered = registration()
    document = report(registered)
    with ThreadPoolExecutor(max_workers=5) as workers:
        results = list(workers.map(lambda _: store.record(ACTOR, registered, document), range(10)))
    assert len(set(results)) == 1 and rows(store, database) == 1
    with pytest.raises(FileNotFoundError):
        store.read(replace(ACTOR, organization_id="other"), registered, results[0])


def test_registered_collector_publishes_to_durable_ledger(store, database):
    registered = registration()
    collector = RegisteredDependencyInventoryCollector(
        registered,
        Mock(collect=Mock(return_value=snapshot(registered, "source"))),
        Mock(collect=Mock(return_value=snapshot(registered, "target"))),
        store.publisher(ACTOR, registered),
        verifier_ref="registered-dependency-collector",
        clock=lambda: NOW,
    )
    observations = collector.collect(registered.scope, (dependency_inventory_requirement(registered),))
    assert len(observations) == 2 and rows(store, database) == 1
    assert store.read(ACTOR, registered, observations[0].evidence_ref)["status"] == "verified"
