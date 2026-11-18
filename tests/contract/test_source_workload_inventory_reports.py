"""Static source evidence is durable and chained into the G1 report ledger."""

from unittest.mock import Mock
from uuid import uuid4

import pytest

from adapters.source.workload_inventory import StaticSourceWorkloadInventoryReader
from adapters.state.deployment_admission import PostgresDeploymentAdmission
from adapters.state.operations import PostgresOperationStore
from adapters.state.source_workload_inventory import PostgresSourceWorkloadInventoryReports
from adapters.state.workload_inventory import PostgresWorkloadInventoryReports
from application.environment_dependency_inventory import (
    RegisteredDependencyInventoryCollector,
    dependency_inventory_requirement,
)
from domain.access import LoginSource, Principal, Role
from ports.environment_transition import PreservationCollectionUnavailable
from tests.contract.test_database_migration_reviews import database as database  # noqa: PLC0414
from tests.unit.test_environment_transition import NOW
from tests.unit.test_source_workload_inventory import python_project, setup
from tests.unit.test_workload_inventory import snapshot

ACTOR = Principal("alice", "org", Role.DEPLOYER, LoginSource.CORPORATE_SSO)


@pytest.fixture
def stores(database):
    admission = PostgresDeploymentAdmission(
        PostgresOperationStore(database, workspace=uuid4().hex),
        account_id="111111111111",
        region="ap-northeast-2",
    )
    source = PostgresSourceWorkloadInventoryReports(admission, current_principal=lambda principal: principal)
    workload = PostgresWorkloadInventoryReports(admission, current_principal=lambda principal: principal)
    source.initialize()
    workload.initialize()
    with database() as db:
        db.execute(
            """INSERT INTO sky_state.application_owners
            (workspace,application_id,organization_id,created_by) VALUES(%s,'app','org','alice')""",
            (admission.operations.workspace,),
        )
    return source, workload


def row_count(store, database, table):
    with database() as db:
        return db.execute(
            f"SELECT count(*) FROM sky_state.{table} WHERE workspace=%s",
            (store.operations.workspace,),
        ).fetchone()[0]


def static_reader(project, source_store):
    template, registered, runtime, _published = setup(project, "python")
    runtime.collect.side_effect = lambda inventory, value: snapshot(inventory, value)
    reader = StaticSourceWorkloadInventoryReader(
        template.registration,
        project,
        runtime,
        source_store.publisher(ACTOR, template.registration),
        clock=lambda: NOW,
    )
    return reader, registered, runtime


def test_source_report_survives_restart_and_is_chained_into_g1(stores, database, tmp_path):
    source_store, workload_store = stores
    project = python_project(tmp_path)
    source_reader, registered, runtime = static_reader(project, source_store)
    target_reader, _, _ = static_reader(project, source_store)
    collector = RegisteredDependencyInventoryCollector(
        registered,
        source_reader,
        target_reader,
        workload_store.publisher(ACTOR, registered),
        verifier_ref="registered-dependency-collector",
        clock=lambda: NOW,
    )

    observations = collector.collect(
        registered.scope,
        (dependency_inventory_requirement(registered),),
    )
    assert len(observations) == 2
    assert row_count(source_store, database, "source_inventory_reports") == 1
    assert row_count(workload_store, database, "workload_inventory_reports") == 1

    workload_report = workload_store.read(ACTOR, registered, observations[0].evidence_ref)
    source_refs = {
        ref
        for endpoint in ("source", "target")
        for ref in workload_report[endpoint]["evidence_refs"]
        if ref.startswith("WSI-")
    }
    assert len(source_refs) == 1
    restarted = PostgresSourceWorkloadInventoryReports(
        source_store.admission,
        current_principal=lambda principal: principal,
    )
    assert restarted.read(ACTOR, source_reader.registration, source_refs.pop())["status"] == "verified"
    restarted.check_ready()
    assert runtime.collect.call_count == 1
    with database() as db:
        assert db.execute(
            "SELECT count(*) FROM sky_state.operations WHERE workspace=%s",
            (source_store.operations.workspace,),
        ).fetchone() == (0,)


def test_blocked_source_report_is_durable_but_never_becomes_g1_evidence(stores, database, tmp_path):
    source_store, workload_store = stores
    project = python_project(tmp_path)
    with (project / "api.py").open("a") as output:
        output.write("\nmodule = __import__(name)\n")
    source_reader, registered, runtime = static_reader(project, source_store)
    collector = RegisteredDependencyInventoryCollector(
        registered,
        source_reader,
        Mock(),
        workload_store.publisher(ACTOR, registered),
        verifier_ref="registered-dependency-collector",
        clock=lambda: NOW,
    )

    with pytest.raises(PreservationCollectionUnavailable):
        collector.collect(
            registered.scope,
            (dependency_inventory_requirement(registered),),
        )
    assert row_count(source_store, database, "source_inventory_reports") == 1
    assert row_count(workload_store, database, "workload_inventory_reports") == 0
    runtime.collect.assert_not_called()
    with database() as db:
        report = db.execute(
            "SELECT document FROM sky_state.source_inventory_reports WHERE workspace=%s",
            (source_store.operations.workspace,),
        ).fetchone()[0]
    assert report["status"] == "blocked" and report["blockers"]
