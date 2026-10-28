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


def test_uncertain_preparation_inspection_uses_readonly_metadata_and_does_not_resolve_operation(
    database, workload_apps
):
    from contextlib import contextmanager
    from dataclasses import asdict
    from unittest.mock import Mock
    from uuid import uuid4

    from adapters.state.operations import PostgresOperationStore
    from adapters.state.postgres import PostgresDeploymentRecordStore
    from application.incident_credential_preparation import FIELD, IncidentCredentialPreparation
    from tests.contract.test_incident_database_restriction import prepare
    from tests.unit.test_operating_review import ID, NOW

    _params, _names, _roles, _held, binding, restriction = workload_apps
    store = PostgresOperationStore(database, workspace="credential-inspection-" + uuid4().hex)
    records, actor, restriction_service, args = prepare(database, store, binding, restriction)
    restricted = restriction_service.restrict(actor, ID, **args)
    preparation = Mock(
        binding=binding, resource_id="db-INSPECTION", principal_arn="arn:aws:iam::111111111111:user/preparer"
    )
    sql_preparation = PostgresIncidentCredentialPreparation(restriction)

    def stage(operation_id, *, guard):
        return {
            **sql_preparation.prepare_password(PASSWORD, guard=guard),
            "resource_id": preparation.resource_id,
            "candidate_access_principal": preparation.principal_arn,
            "candidate_secret_ref": f"arn:aws:secretsmanager:{binding.region}:{binding.account_id}:secret:sky-incident/{preparation.resource_id}/{operation_id}-test01",
            "candidate_version_id": operation_id,
            "runtime_access_granted": False,
        }

    preparation.prepare.side_effect = stage
    service = IncidentCredentialPreparation(
        records, restriction, preparation, clock=lambda: NOW, revalidate=lambda: actor
    )
    args.update(
        expected_operation_id=restricted["operation_id"], expected_revision=records.load_job(ID).revision
    )
    prepared = service.prepare(actor, ID, **args)
    # Model a lost completion record while the SQL password was already written.
    intent = {
        k: v
        for k, v in prepared.items()
        if k
        not in {
            "candidate_secret_ref",
            "candidate_version_id",
            "prepared_at",
            "password_update_acknowledged",
            "login_enabled",
            "active_sessions",
            "authentication_verified",
            "runtime_access_granted",
        }
    }
    intent["phase"] = "applying"
    snapshot = records.load_job(ID)
    service.writer.patch(actor, ID, snapshot.revision, {FIELD: intent})

    @contextmanager
    def read_only_state():
        with database() as db:
            db.execute("SET TRANSACTION READ ONLY")
            with pytest.raises(psycopg.errors.ReadOnlySqlTransaction), db.transaction():
                db.execute("UPDATE sky_state.metadata_records SET revision=revision WHERE false")
            yield db

    def inspect(operation_id, *, guard):
        return {
            **restriction.inspect(guard=guard),
            "resource_id": preparation.resource_id,
            "candidate_access_principal": preparation.principal_arn,
            "candidate_state": "registered_candidate",
            "candidate_secret_ref": prepared["candidate_secret_ref"],
            "candidate_version_id": operation_id,
            "password_update_verified": False,
            "authentication_verified": False,
        }

    preparation.inspect.side_effect = inspect
    preparation.prepare.reset_mock()
    preparation.prepare.side_effect = AssertionError("Inspection replayed preparation")
    reads = PostgresDeploymentRecordStore(read_only_state, workspace=records.workspace)
    inspection_service = IncidentCredentialPreparation(
        reads, restriction, preparation, clock=lambda: NOW, revalidate=lambda: actor
    )
    before = records.load_job(ID)
    args.update(expected_operation_id=prepared["operation_id"], expected_revision=before.revision)
    receipt = inspection_service.inspect(actor, ID, **args)
    assert receipt["persisted_phase"] == "applying" and receipt["state_changed"] is False
    assert receipt["password_update_verified"] is False and receipt["execution_exclusion_verified"] is False
    assert receipt["observed_state"] == "restricted_candidate_observed"
    assert records.load_job(ID) == before
    assert receipt["binding"] == asdict(binding)
    preparation.prepare.assert_not_called()
