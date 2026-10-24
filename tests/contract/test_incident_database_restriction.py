"""Real disposable SQL proves one login/session scope and durable state."""

import os
from contextlib import contextmanager
from dataclasses import asdict
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

from adapters.database.incident_restriction import PostgresIncidentRestriction
from adapters.database.promotion_fence import PostgresApplicationFence
from adapters.state.postgres import PostgresDeploymentRecordStore
from application.incident_database_restriction import FIELD, IncidentDatabaseRestriction
from application.security_hold import SecurityHold
from domain.access import Role
from domain.database import DatabaseBinding
from tests.contract.test_operation_store import database as database  # noqa: PLC0414
from tests.contract.test_operation_store import store as store  # noqa: PLC0414
from tests.unit.test_deployment_writes import Records, principal
from tests.unit.test_operating_review import ID, NOW


@pytest.fixture
def workload_apps(database):
    params = conninfo_to_dict(os.environ["SKY_TEST_POSTGRES_DSN"])
    assert params["host"] == "127.0.0.1"
    nonce = uuid4().hex[:12]
    names = ["incident_a_" + nonce, "incident_b_" + nonce]
    roles = ["sky_login_a_" + nonce, "sky_login_b_" + nonce]
    markers = ["sky-pool-allocation-v1:a-" + nonce, "sky-pool-allocation-v1:b-" + nonce]
    held = []
    with psycopg.connect(**params, autocommit=True) as root:
        try:
            for name, role, marker in zip(names, roles, markers):
                root.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
                root.execute(
                    sql.SQL(
                        "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD 'disposable-only'"
                    ).format(sql.Identifier(role))
                )
                root.execute(
                    sql.SQL("COMMENT ON ROLE {} IS {}").format(sql.Identifier(role), sql.Literal(marker))
                )
                root.execute(
                    sql.SQL("COMMENT ON DATABASE {} IS {}").format(sql.Identifier(name), sql.Literal(marker))
                )
                root.execute(
                    sql.SQL("REVOKE CONNECT ON DATABASE {} FROM PUBLIC").format(sql.Identifier(name))
                )
                root.execute(
                    sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                        sql.Identifier(name), sql.Identifier(role)
                    )
                )
                with psycopg.connect(**{**params, "dbname": name}) as db:
                    db.execute("CREATE TABLE scores(id integer primary key, score integer)")
                    db.execute("INSERT INTO scores VALUES(1,42)")
                    db.execute(sql.SQL("GRANT SELECT,INSERT ON scores TO {}").format(sql.Identifier(role)))
                held.append(
                    psycopg.connect(
                        **{**params, "dbname": name, "user": role, "password": "disposable-only"},
                        autocommit=True,
                    )
                )
            binding = DatabaseBinding(
                "org1", "game", "shared_workload", "111111111111", "ap-northeast-2", "pool", names[0], nonce
            )

            @contextmanager
            def connect():
                with psycopg.connect(**{**params, "dbname": names[0]}) as db:
                    yield db

            fence = PostgresApplicationFence(connect, binding, roles[0], markers[0])
            yield params, names, roles, held, binding, PostgresIncidentRestriction(fence)
        finally:
            for connection in held:
                connection.close()
            for name in names:
                root.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name)))
            for role in roles:
                root.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))


def prepare(database, store, binding, adapter):
    records = PostgresDeploymentRecordStore(database, workspace=store.workspace)
    job = {
        **Records().job,
        "status": "succeeded",
        "deployment_state": "active",
        "workload_database_binding": asdict(binding),
    }
    records.save_job(ID, job, expected_revision=None)
    actor = principal(role=Role.ADMIN)
    SecurityHold(records).place(actor, ID, incident_id="INC-sql", reason="credential_exposure", now=NOW)
    snapshot = records.load_job(ID)
    service = IncidentDatabaseRestriction(records, adapter, clock=lambda: NOW, revalidate=lambda: actor)
    args = {
        "incident_id": "INC-sql",
        "expected_boundary": snapshot.record["security_review_boundary"]["id"],
        "expected_revision": snapshot.revision,
    }
    return records, actor, service, args


def test_one_app_login_and_sessions_are_restricted_other_app_and_data_survive(database, store, workload_apps):
    params, names, roles, held, binding, adapter = workload_apps
    records, actor, service, args = prepare(database, store, binding, adapter)
    result = service.restrict(actor, ID, **args)
    assert result["phase"] == "verified"
    with pytest.raises(psycopg.OperationalError):
        held[0].execute("SELECT * FROM scores")
    with pytest.raises(psycopg.OperationalError):
        psycopg.connect(**{**params, "dbname": names[0], "user": roles[0], "password": "disposable-only"})
    assert held[1].execute("SELECT score FROM scores WHERE id=1").fetchone() == (42,)
    with psycopg.connect(
        **{**params, "dbname": names[1], "user": roles[1], "password": "disposable-only"}
    ) as other:
        assert other.execute("SELECT 1").fetchone() == (1,)
    with psycopg.connect(**{**params, "dbname": names[0]}) as root:
        assert root.execute("SELECT score FROM scores WHERE id=1").fetchone() == (42,)
        assert root.execute("SELECT rolcanlogin FROM pg_roles WHERE rolname=%s", (roles[0],)).fetchone() == (
            False,
        )
    saved = records.load_job(ID)
    assert saved.record["security_hold"]["incident_id"] == "INC-sql"
    assert service.restrict(actor, ID, **args) == result and records.load_job(ID) == saved
    with pytest.raises(ValueError, match="dedicated incident recovery"):
        SecurityHold(records).release_false_positive(
            actor,
            ID,
            incident_id="INC-sql",
            review_ref="false-positive",
            expected_revision=saved.revision,
            expected_boundary=args["expected_boundary"],
            now=NOW,
        )


def test_unowned_role_is_not_modified_and_uncertainty_is_recorded(database, store, workload_apps):
    params, names, roles, held, binding, adapter = workload_apps
    records, actor, service, args = prepare(database, store, binding, adapter)
    with psycopg.connect(**{**params, "dbname": names[0]}) as root:
        root.execute(sql.SQL("COMMENT ON ROLE {} IS 'unowned'").format(sql.Identifier(roles[0])))
    with pytest.raises(OSError):
        service.restrict(actor, ID, **args)
    assert records.load_job(ID).record[FIELD]["phase"] == "needs_attention"
    assert held[0].execute("SELECT 1").fetchone() == (1,)
    assert held[1].execute("SELECT 1").fetchone() == (1,)
    with psycopg.connect(**{**params, "dbname": names[0]}) as root:
        assert root.execute("SELECT rolcanlogin FROM pg_roles WHERE rolname=%s", (roles[0],)).fetchone() == (
            True,
        )
    assert service.restrict(actor, ID, **args)["phase"] == "needs_attention"
