"""Read-only metadata collection must fail closed on ownership or transport drift."""

import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

import pytest

from adapters.database.migration_inventory import PostgresInventoryRegistration, PostgresMigrationInventory
from domain.database_inventory import DatabaseInventoryUnavailable, DatabaseResourceEvidence
from domain.database_migration import DatabaseLocation, DatabasePlacement

NOW = datetime(2026, 10, 30, 12, tzinfo=UTC)
CA = b"-----BEGIN CERTIFICATE-----\npinned-test-ca\n-----END CERTIFICATE-----\n"


@pytest.fixture
def reader(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_bytes(CA)
    placement = DatabasePlacement(
        "org",
        "app",
        "shared_workload",
        DatabaseLocation("onprem", "vm_postgresql", "vm-1", "dc-a"),
        "postgres-1",
        "app_db",
        "owner",
        17,
    )
    config = PostgresInventoryRegistration(
        placement, "db.example", 5432, "collector", str(ca), hashlib.sha256(ca.read_bytes()).hexdigest()
    )
    db = MagicMock()
    params = {
        "sslmode": "verify-full",
        "sslrootcert": str(ca),
        "host": "db.example",
        "port": "5432",
        "dbname": "app_db",
        "user": "collector",
    }
    db.info = SimpleNamespace(get_parameters=lambda: params)
    db.pgconn = SimpleNamespace(ssl_in_use=True)

    def execute(statement, *args):
        cursor = Mock()
        if "current_setting('server_version_num')" in statement:
            cursor.fetchone.return_value = ("app_db", "collector", 170005, "UTF8", "C", "C")
        elif "SELECT extname,extversion" in statement:
            cursor.fetchall.return_value = [("plpgsql", "1.0")]
        else:
            cursor.fetchone.return_value = (1,)
        return cursor

    db.execute.side_effect = execute
    connect = MagicMock()
    connect.return_value.__enter__.return_value = db
    verifier = Mock(
        verify=Mock(
            return_value=DatabaseResourceEvidence(placement, "actual-audit-1", NOW, "db.example", 5432)
        )
    )
    value = PostgresMigrationInventory(
        config, connect=connect, resource_verifier=verifier, clock=lambda: NOW, metadata_budget_seconds=30
    )
    return value, db, params, ca


def collect(reader):
    return reader.inspect(reader.registration.resource, plan_id="DBM-" + "a" * 64)


def test_reads_only_metadata_and_reuses_existing_schema_profile(reader):
    value, db, _, _ = reader
    with patch(
        "adapters.database.migration_inventory._inventory", return_value=[("scores", [], [])]
    ) as schema:
        result = collect(value)
    assert result.server_version_num == 170005
    assert result.resource.evidence_ref == "actual-audit-1"
    assert result.schema_status == "supported" and result.table_count == 1
    statements = [c.args[0] for c in db.execute.call_args_list]
    assert statements[0] == "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
    assert all(sql.startswith(("SET ", "SELECT ")) for sql in statements)
    assert not any("SELECT *" in sql for sql in statements)
    schema.assert_called_once()
    assert callable(schema.call_args.kwargs["guard"])


def test_foreign_registration_rejected_before_verifier_or_connection(reader):
    value, _, _, _ = reader
    with pytest.raises(ValueError, match="registration"):
        value.inspect(
            replace(value.registration.resource, application_id="foreign"), plan_id="DBM-" + "a" * 64
        )
    value.connect.assert_not_called()
    value.resource_verifier.verify.assert_not_called()


@pytest.mark.parametrize("change", [{"server_hostname": "foreign.example"}, {"server_port": 6432}])
def test_provider_proof_must_match_registered_connection_before_connect(reader, change):
    value, _, _, _ = reader
    value.resource_verifier.verify.return_value = replace(
        value.resource_verifier.verify.return_value, **change
    )
    with pytest.raises(DatabaseInventoryUnavailable):
        collect(value)
    value.connect.assert_not_called()


@pytest.mark.parametrize(
    ("key", "new"),
    [
        ("sslmode", "require"),
        ("sslmode", "verify-ca"),
        ("host", "foreign.example"),
        ("port", "6432"),
        ("dbname", "foreign"),
        ("user", "foreign"),
        ("sslrootcert", "/other/ca.pem"),
    ],
)
def test_tls_and_connection_drift_rejected_before_sql(reader, key, new):
    value, db, params, _ = reader
    params[key] = new
    with pytest.raises(DatabaseInventoryUnavailable):
        collect(value)
    db.execute.assert_not_called()


def test_encryption_is_checked_in_addition_to_verify_full_configuration(reader):
    value, db, _, _ = reader
    db.pgconn.ssl_in_use = False
    with pytest.raises(DatabaseInventoryUnavailable):
        collect(value)
    db.execute.assert_not_called()


@pytest.mark.parametrize("change", ["digest", "mode", "symlink", "non-pem"])
def test_untrusted_ca_file_fails_before_connect(reader, tmp_path, change):
    value, _, _, ca = reader
    if change == "digest":
        ca.write_bytes(CA.replace(b"pinned", b"changed"))
    elif change == "mode":
        ca.chmod(0o666)
    elif change == "symlink":
        replacement = tmp_path / "replacement.pem"
        replacement.write_bytes(CA)
        ca.unlink()
        ca.symlink_to(replacement)
    else:
        ca.write_bytes(b"not-a-pem-ca")
        value.registration = replace(
            value.registration,
            ca_sha256=hashlib.sha256(ca.read_bytes()).hexdigest(),
        )
    with pytest.raises(DatabaseInventoryUnavailable):
        collect(value)
    value.connect.assert_not_called()


def test_unsupported_schema_is_distinct_from_failed_collection(reader):
    value, _, _, _ = reader
    with patch(
        "adapters.database.migration_inventory._inventory", side_effect=ValueError("Unsupported index")
    ):
        result = collect(value)
    assert result.schema_status == "unsupported" and result.schema_sha256 is None


def test_query_failures_do_not_become_unsupported_schema_or_leak_details(reader):
    import psycopg

    value, db, _, _ = reader
    db.execute.side_effect = psycopg.OperationalError("password=CANARY-SECRET")
    with pytest.raises(DatabaseInventoryUnavailable) as exc:
        collect(value)
    assert "CANARY-SECRET" not in str(exc.value)
    assert exc.value.__suppress_context__


def test_provider_failure_diagnostics_are_sanitized(reader):
    value, _, _, _ = reader
    value.resource_verifier.verify.side_effect = RuntimeError("token=CANARY-SECRET")
    with pytest.raises(DatabaseInventoryUnavailable) as exc:
        collect(value)
    assert "CANARY-SECRET" not in str(exc.value)
    value.connect.assert_not_called()


def test_metadata_deadline_prevents_further_queries(reader):
    value, db, _, _ = reader
    value.monotonic = Mock(side_effect=[0, 31])
    with pytest.raises(DatabaseInventoryUnavailable):
        collect(value)
    value.connect.assert_not_called()
    db.execute.assert_not_called()
