"""Real TLS PostgreSQL metadata; optional native pinned-SSH VM resource verification.

Run only with two explicitly disposable loopback databases and pinned test CA.
This does not prove AWS/VM ownership integration, copying, or traffic cutover.
"""

import hashlib
import json
import os
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock

import pytest

psycopg = pytest.importorskip("psycopg")

from adapters.database.migration_inventory import PostgresInventoryRegistration, PostgresMigrationInventory
from adapters.onprem.database_inventory import (
    PinnedVmInventoryCommand,
    VmDatabaseInventoryRegistration,
    VmDatabaseInventoryVerifier,
)
from application.database_migration_preflight import DatabaseMigrationPreflight
from domain.database_inventory import DatabaseInventoryUnavailable, DatabaseResourceEvidence
from domain.database_migration import DatabaseLocation, DatabasePlacement, MigrationSafetyPolicy


@pytest.fixture
def databases():
    dsns = [os.environ.get("SKY_TEST_MIGRATION_SOURCE_DSN"), os.environ.get("SKY_TEST_MIGRATION_TARGET_DSN")]
    ca = os.environ.get("SKY_TEST_MIGRATION_CA")
    if not all(dsns) or not ca:
        pytest.skip("Two disposable TLS PostgreSQL databases and CA required")
    parameters = [psycopg.conninfo.conninfo_to_dict(dsn) for dsn in dsns]
    for value in parameters:
        assert value["host"] == "127.0.0.1" and value["dbname"].startswith("inventory_")
        assert value["sslmode"] == "verify-full" and value["sslrootcert"] == ca
    assert parameters[0]["port"] != parameters[1]["port"]
    connects = [lambda params=params: psycopg.connect(**params) for params in parameters]
    with connects[0]() as db:
        db.execute("CREATE TABLE scores(id integer PRIMARY KEY, score bigint NOT NULL)")
        db.execute("INSERT INTO scores VALUES (1,42),(2,84)")
        major = db.execute("SHOW server_version_num").fetchone()[0]
    placements, readers = [], []
    for index, (params, connect) in enumerate(zip(parameters, connects)):
        placement = DatabasePlacement(
            "local-validation",
            "inventory-validation",
            "existing_workload",
            DatabaseLocation("onprem", "vm_postgresql", "registered-test-vm", "local-validation"),
            "disposable-instance-" + str(index),
            params["dbname"],
            "operator-test-owner",
            int(major) // 10000,
        )
        registration = PostgresInventoryRegistration(
            placement,
            params["host"],
            int(params["port"]),
            params["user"],
            ca,
            hashlib.sha256(Path(ca).read_bytes()).hexdigest(),
        )
        # This explicit double tests SQL/TLS, not provider ownership. Production
        # registration must provide a verifier backed by actual provider checks.
        verifier = Mock()
        verifier.verify.side_effect = lambda requested, params=params: DatabaseResourceEvidence(
            requested,
            "controlled-resource-proof",
            datetime.now(UTC),
            params["host"],
            int(params["port"]),
        )
        native_registration = os.environ.get("SKY_TEST_VM_INVENTORY_REGISTRATION")
        if native_registration:
            document = json.loads(Path(native_registration).read_text())
            spec = document["registrations"][index]
            pinned = VmDatabaseInventoryRegistration(**{**spec, "placement": placement})
            assert spec["placement"] == {
                **placement.__dict__,
                "location": placement.location.__dict__,
            }
            verifier = VmDatabaseInventoryVerifier(
                pinned,
                PinnedVmInventoryCommand(**document["ssh"]),
                clock=lambda: datetime.now(UTC),
            )
        readers.append(
            PostgresMigrationInventory(
                registration,
                connect=connect,
                resource_verifier=verifier,
                clock=lambda: datetime.now(UTC),
                metadata_budget_seconds=30,
            )
        )
        placements.append(placement)
    try:
        yield placements, readers, connects
    finally:
        for connect in connects:
            with connect() as db:
                db.execute("DROP VIEW IF EXISTS score_view")
                db.execute("DROP TABLE IF EXISTS scores")


def inspect(databases):
    placements, readers, _ = databases
    return DatabaseMigrationPreflight(
        *readers,
        clock=lambda: datetime.now(UTC),
        max_age_seconds=60,
    ).inspect(*placements, MigrationSafetyPolicy(120, 600, 86400), source_revision="a" * 64)


def test_actual_tls_metadata_does_not_copy_or_change_source_data(databases):
    result = inspect(databases)
    assert result["preflight"]["status"] == "passed"
    assert result["preflight"]["inventories"]["source"]["table_count"] == 1
    assert result["preflight"]["inventories"]["target"]["table_count"] == 0
    assert result["blockers"] == ["route_not_implemented"]
    assert result["execution_status"] == "blocked" and not result["ready_to_cutover"]
    with databases[2][0]() as src, databases[2][1]() as dst:
        assert src.execute("SELECT * FROM scores ORDER BY id").fetchall() == [(1, 42), (2, 84)]
        assert dst.execute("SELECT to_regclass('public.scores')").fetchone() == (None,)


def test_actual_unsupported_view_is_not_silently_ignored(databases):
    with databases[2][0]() as db:
        db.execute("CREATE VIEW score_view AS SELECT id FROM scores")
    result = inspect(databases)
    assert result["preflight"]["inventories"]["source"]["schema_status"] == "unsupported"
    assert "preflight_schema_and_extensions_incompatible" in result["blockers"]


def test_actual_nonempty_destination_is_blocked_without_overwrite(databases):
    with databases[2][1]() as db:
        db.execute("CREATE TABLE scores(id integer PRIMARY KEY, score bigint NOT NULL)")
        db.execute("INSERT INTO scores VALUES(3,999)")
    result = inspect(databases)
    assert "preflight_schema_and_extensions_incompatible" in result["blockers"]
    with databases[2][1]() as db:
        assert db.execute("SELECT * FROM scores").fetchall() == [(3, 999)]


def test_actual_version_is_compared_to_declared_version(databases):
    placements, readers, _ = databases
    placements[0] = replace(placements[0], postgres_major=placements[0].postgres_major + 1)
    readers[0].registration = replace(readers[0].registration, resource=placements[0])
    if isinstance(readers[0].resource_verifier, VmDatabaseInventoryVerifier):
        verifier = readers[0].resource_verifier
        verifier.registration = replace(verifier.registration, placement=placements[0])
    assert "preflight_declared_versions_incompatible" in inspect(databases)["blockers"]


def test_actual_read_only_transaction_and_query_timeout(databases):
    from contextlib import contextmanager

    reader = databases[1][0]
    connect = reader.connect

    @contextmanager
    def checking_connection():
        with connect() as db:
            yield db
            assert db.execute("SHOW transaction_read_only").fetchone() == ("on",)
            assert db.execute("SHOW statement_timeout").fetchone() == ("5s",)
            assert db.execute("SHOW transaction_isolation").fetchone() == ("repeatable read",)
            with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
                db.execute("INSERT INTO public.scores VALUES(3,999)")
            db.rollback()

    reader.connect = checking_connection
    assert inspect(databases)["preflight"]["status"] == "passed"


def test_actual_untrusted_ca_is_rejected_without_driver_diagnostics(databases):
    bad_ca = os.environ.get("SKY_TEST_MIGRATION_UNTRUSTED_CA")
    if not bad_ca:
        pytest.skip("Separate untrusted test CA required")
    reader = databases[1][0]
    params = psycopg.conninfo.conninfo_to_dict(os.environ["SKY_TEST_MIGRATION_SOURCE_DSN"])
    reader.registration = replace(
        reader.registration,
        sslrootcert=bad_ca,
        ca_sha256=hashlib.sha256(Path(bad_ca).read_bytes()).hexdigest(),
    )
    reader.connect = lambda: psycopg.connect(**{**params, "sslrootcert": bad_ca})
    with pytest.raises(DatabaseInventoryUnavailable) as exc:
        reader.inspect(databases[0][0], plan_id="DBM-" + "a" * 64)
    assert str(exc.value) == "Registered database inventory unavailable"
