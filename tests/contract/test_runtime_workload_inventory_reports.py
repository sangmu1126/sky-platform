"""Linux /proc evidence is durable before it can enter the G1 report ledger."""

import hashlib
import json
from copy import deepcopy
from dataclasses import replace
from uuid import uuid4

import pytest

from adapters.runtime.workload_inventory import (
    LinuxProcWorkloadInventoryReader,
    RemoteLinuxWorkloadInventoryReader,
    collect_linux_proc_observation,
)
from adapters.source.workload_inventory import StaticSourceWorkloadInventoryReader
from adapters.state.deployment_admission import PostgresDeploymentAdmission
from adapters.state.operations import PostgresOperationStore
from adapters.state.provider_identity import PostgresProviderIdentityReports
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
from tests.unit.test_provider_identity import provider_runtime_case
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
        runtime_registration = replace(
            template.registration,
            endpoint=endpoint,
            authority_ref="contract-remote" if endpoint == "target" else "local-proc",
        )
        runtime_registrations[endpoint] = runtime_registration
        if endpoint == "source":
            runtime_reader = LinuxProcWorkloadInventoryReader(
                runtime_registration,
                proc,
                runtime_store.publisher(ACTOR, runtime_registration),
                clock=lambda: NOW,
            )
        else:
            observation = collect_linux_proc_observation(
                runtime_registration.document(), proc, clock=lambda: NOW
            )

            class Transport:
                def __init__(self, registration, observation):
                    self.registration = registration
                    self.observation = observation

                def observe(self, registration):
                    assert registration == self.registration
                    return self.observation

            runtime_reader = RemoteLinuxWorkloadInventoryReader(
                runtime_registration,
                Transport(runtime_registration, observation),
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


def test_provider_identity_is_durable_and_bound_into_runtime_report(stores, database, tmp_path):
    runtime_store, _source_store, _workload_store = stores
    reader, source, _runtime_reports, _provider_reports = provider_runtime_case(tmp_path)
    provider_registration = reader.provider_identity_reader.registration
    provider_store = PostgresProviderIdentityReports(
        runtime_store.admission, current_principal=lambda principal: principal
    )
    provider_store.initialize()
    reader.provider_identity_reader.publisher = provider_store.publisher(ACTOR, provider_registration)
    reader.publisher = runtime_store.publisher(ACTOR, reader.registration)

    snapshot = reader.collect(source.inventory, "source")
    provider_ref = next(value for value in snapshot.evidence_refs if value.startswith("WPI-"))
    runtime_ref = next(value for value in snapshot.evidence_refs if value.startswith("WRI-"))
    assert provider_store.read(ACTOR, provider_registration, provider_ref)["status"] == "verified"
    runtime_report = runtime_store.read(ACTOR, reader.registration, runtime_ref)
    assert runtime_report["provider_identity_report_id"] == provider_ref
    fabricated = deepcopy(runtime_report)
    fabricated["provider_identity_report_id"] = "WPI-" + "f" * 64
    unsigned = {key: value for key, value in fabricated.items() if key != "report_id"}
    fabricated["report_id"] = (
        "WRI-"
        + hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
    )
    with pytest.raises(ValueError, match="Durable provider identity"):
        runtime_store.record(ACTOR, reader.registration, fabricated)
    provider_store.check_ready()
    with database() as db:
        workspace = runtime_store.operations.workspace
        counts = {
            table: db.execute(
                f"SELECT count(*) FROM sky_state.{table} WHERE workspace=%s",
                (workspace,),
            ).fetchone()[0]
            for table in ("provider_identity_reports", "runtime_inventory_reports", "operations")
        }
    assert counts == {
        "provider_identity_reports": 1,
        "runtime_inventory_reports": 1,
        "operations": 0,
    }
