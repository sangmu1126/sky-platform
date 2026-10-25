"""Real SQL password preparation with NOLOGIN retained; manual login only in test."""

import psycopg
import pytest
from psycopg import sql

from adapters.database.incident_credentials import PostgresIncidentCredentialPreparation
from tests.contract.test_incident_database_restriction import workload_apps as workload_apps  # noqa: PLC0414
from tests.contract.test_operation_store import database as database  # noqa: PLC0414

PASSWORD = "new-disposable-incident-password-for-contract-only"


def test_password_changes_while_restricted_and_old_password_cannot_authenticate(workload_apps):
    params, names, roles, held, _binding, restriction = workload_apps
    restriction.restrict(guard=lambda: None)
    result = PostgresIncidentCredentialPreparation(restriction).prepare_password(PASSWORD, guard=lambda: None)
    assert result["login_enabled"] is False and result["authentication_verified"] is False
    assert PASSWORD not in str(result)
    with pytest.raises(psycopg.OperationalError):
        psycopg.connect(**{**params, "dbname": names[0], "user": roles[0], "password": PASSWORD})
    assert held[1].execute("SELECT score FROM scores").fetchone() == (42,)
    with psycopg.connect(**params, autocommit=True) as admin:
        assert admin.execute("SELECT rolcanlogin FROM pg_roles WHERE rolname=%s", (roles[0],)).fetchone() == (
            False,
        )
        # Only the disposable test administrator enables login to prove the
        # password write; no product restoration method is involved.
        admin.execute(sql.SQL("ALTER ROLE {} LOGIN").format(sql.Identifier(roles[0])))
        try:
            with pytest.raises(psycopg.OperationalError):
                psycopg.connect(
                    **{**params, "dbname": names[0], "user": roles[0], "password": "disposable-only"}
                )
            with psycopg.connect(
                **{**params, "dbname": names[0], "user": roles[0], "password": PASSWORD}
            ) as db:
                assert db.execute("SELECT score FROM scores").fetchone() == (42,)
        finally:
            admin.execute(sql.SQL("ALTER ROLE {} NOLOGIN").format(sql.Identifier(roles[0])))


def test_unrestricted_application_is_not_modified(workload_apps):
    params, names, roles, _held, _binding, restriction = workload_apps
    with pytest.raises(ValueError):
        PostgresIncidentCredentialPreparation(restriction).prepare_password(PASSWORD, guard=lambda: None)
    with psycopg.connect(
        **{**params, "dbname": names[0], "user": roles[0], "password": "disposable-only"}
    ) as db:
        assert db.execute("SELECT score FROM scores").fetchone() == (42,)


def test_revocation_after_commit_never_reenables_login_or_retries_password_write(workload_apps):
    params, _names, roles, _held, _binding, restriction = workload_apps
    restriction.restrict(guard=lambda: None)
    with psycopg.connect(**params, autocommit=True) as root:
        original = root.execute("SELECT rolpassword FROM pg_authid WHERE rolname=%s", (roles[0],)).fetchone()

        def guard():
            current = root.execute(
                "SELECT rolpassword FROM pg_authid WHERE rolname=%s", (roles[0],)
            ).fetchone()
            if current != original:
                raise PermissionError("Test membership revoked after commit")

        with pytest.raises(PermissionError):
            PostgresIncidentCredentialPreparation(restriction).prepare_password(PASSWORD, guard=guard)
        assert root.execute("SELECT rolcanlogin FROM pg_roles WHERE rolname=%s", (roles[0],)).fetchone() == (
            False,
        )
