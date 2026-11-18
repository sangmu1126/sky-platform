"""Linux /proc evidence is durable before it can enter the G1 report ledger."""

from dataclasses import replace
from uuid import uuid4

import pytest

from adapters.runtime.workload_inventory import LinuxProcWorkloadInventoryReader
from adapters.source.workload_inventory import StaticSourceWorkloadInventoryReader
from adapters.state.deployment_admission import PostgresDeploymentAdmission
from adapters.state.operations import PostgresOperationStore
from adapters.state.runtime_workload_inventory import PostgresRuntimeWorkloadInventoryReports
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
from tests.unit.test_runtime_workload_inventory import runtime_case

ACTOR = Principal("alice", "org", Role.DEPLOYER, LoginSource.CORPORATE_SSO)


@pytest.fixture
def stores(database):
    admission = PostgresDeploymentAdmission(
        PostgresOperationStore(database, workspace=uuid4().hex),
        account_id="111111111111",
        region="ap-northeast-2",
    )
    runtime = PostgresRuntimeWorkloadInventoryReports(
        admission, current_principal=lambda principal: principal
    )
    source = PostgresSourceWorkloadInventoryReports(admission, current_principal=lambda principal: principal)
    workload = PostgresWorkloadInventoryReports(admission, current_principal=lambda principal: principal)
    runtime.initialize()
    source.initialize()
    workload.initialize()
    with database() as db:
        db.execute(
            """INSERT INTO sky_state.application_owners
            (workspace,application_id,organization_id,created_by) VALUES(%s,'app','org','alice')""",
            (admission.operations.workspace,),
        )
    return runtime, source, workload


def test_proc_source_and_g1_evidence_form_one_durable_chain(stores, database, tmp_path):
    runtime_store, source_store, workload_store = stores
    template, source_registration, proc, _published = runtime_case(tmp_path)
    readers = {}
    runtime_registrations = {}
    for endpoint in ("source", "target"):
        runtime_registration = replace(template.registration, endpoint=endpoint)
        runtime_registrations[endpoint] = runtime_registration
        runtime_reader = LinuxProcWorkloadInventoryReader(
            runtime_registration,
            proc,
            runtime_store.publisher(ACTOR, runtime_registration),
            clock=lambda: NOW,
        )
        readers[endpoint] = StaticSourceWorkloadInventoryReader(
            source_registration,
            tmp_path / "project",
            runtime_reader,
            source_store.publisher(ACTOR, source_registration),
            clock=lambda: NOW,
        )
    collector = RegisteredDependencyInventoryCollector(
        source_registration.inventory,
        readers["source"],
        readers["target"],
        workload_store.publisher(ACTOR, source_registration.inventory),
        verifier_ref="registered-dependency-collector",
        clock=lambda: NOW,
    )

    observations = collector.collect(
        source_registration.inventory.scope,
        (dependency_inventory_requirement(source_registration.inventory),),
    )
    report = workload_store.read(
        ACTOR,
        source_registration.inventory,
        observations[0].evidence_ref,
    )
    runtime_refs = {
        endpoint: next(value for value in report[endpoint]["evidence_refs"] if value.startswith("WRI-"))
        for endpoint in ("source", "target")
    }
    for endpoint, report_id in runtime_refs.items():
        assert runtime_store.read(ACTOR, runtime_registrations[endpoint], report_id)["status"] == "verified"
    runtime_store.check_ready()
    with database() as db:
        workspace = runtime_store.operations.workspace
        counts = {
            table: db.execute(
                f"SELECT count(*) FROM sky_state.{table} WHERE workspace=%s",
                (workspace,),
            ).fetchone()[0]
            for table in (
                "runtime_inventory_reports",
                "source_inventory_reports",
                "workload_inventory_reports",
                "operations",
            )
        }
    assert counts == {
        "runtime_inventory_reports": 2,
        "source_inventory_reports": 1,
        "workload_inventory_reports": 1,
        "operations": 0,
    }


def test_unregistered_writer_is_durable_blocked_and_never_reaches_g1(stores, database, tmp_path):
    runtime_store, source_store, workload_store = stores
    template, source_registration, proc, _published = runtime_case(tmp_path)
    (proc / "202/fd/9").symlink_to("/private/leak.txt")
    (proc / "202/fdinfo/9").write_text("pos:\t0\nflags:\t100001\n")
    runtime_reader = LinuxProcWorkloadInventoryReader(
        template.registration,
        proc,
        runtime_store.publisher(ACTOR, template.registration),
        clock=lambda: NOW,
    )
    source_reader = StaticSourceWorkloadInventoryReader(
        source_registration,
        tmp_path / "project",
        runtime_reader,
        source_store.publisher(ACTOR, source_registration),
        clock=lambda: NOW,
    )
    collector = RegisteredDependencyInventoryCollector(
        source_registration.inventory,
        source_reader,
        source_reader,
        workload_store.publisher(ACTOR, source_registration.inventory),
        verifier_ref="registered-dependency-collector",
        clock=lambda: NOW,
    )
    with pytest.raises(PreservationCollectionUnavailable):
        collector.collect(
            source_registration.inventory.scope,
            (dependency_inventory_requirement(source_registration.inventory),),
        )
    with database() as db:
        runtime_report = db.execute(
            "SELECT document FROM sky_state.runtime_inventory_reports WHERE workspace=%s",
            (runtime_store.operations.workspace,),
        ).fetchone()[0]
        workload_count = db.execute(
            "SELECT count(*) FROM sky_state.workload_inventory_reports WHERE workspace=%s",
            (runtime_store.operations.workspace,),
        ).fetchone()[0]
    assert runtime_report["status"] == "blocked"
    assert runtime_report["processes"][1]["unexpected_writer_count"] == 1
    assert "/private/leak.txt" not in str(runtime_report)
    assert workload_count == 0
