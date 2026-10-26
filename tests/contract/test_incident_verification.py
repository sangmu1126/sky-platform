"""Actual password authentication and snapshot equality on disposable PostgreSQL."""

from unittest.mock import Mock

import psycopg
import pytest

from adapters.database.incident_credentials import PostgresIncidentCredentialPreparation
from adapters.database.incident_verification import PostgresIncidentVerification, database_fingerprint
from tests.contract.test_incident_database_restriction import workload_apps as workload_apps  # noqa: PLC0414
from tests.contract.test_operation_store import database as database  # noqa: PLC0414

PASSWORD = "rotated-disposable-credential-at-least-32-characters"


def verifier(workload_apps):
    params, names, roles, _, binding, restriction = workload_apps
    workload = lambda: psycopg.connect(**{**params, "dbname": names[0]})
    login = lambda password: psycopg.connect(
        **{**params, "dbname": names[0], "user": roles[0], "password": password}
    )
    service = PostgresIncidentVerification(restriction, workload_connect=workload, login_connect=login)
    with workload() as db:
        baseline = database_fingerprint(db, binding)
    restriction.restrict(guard=lambda: None)
    PostgresIncidentCredentialPreparation(restriction).prepare_password(PASSWORD, guard=lambda: None)
    return service, baseline


def test_real_old_password_rejection_new_authentication_and_refencing(workload_apps):
    service, baseline = verifier(workload_apps)
    report = service.verify(
        candidate_password=PASSWORD,
        previous_password="disposable-only",
        expected_fingerprint=baseline,
        guard=lambda: None,
    )
    assert report["authentication_verified"] and report["previous_password_rejected"]
    assert report["baseline_matched"] and not report["credentials_activated"]
    assert not report["login_enabled"] and report["active_sessions"] == 0
    assert PASSWORD not in str(report)
    with pytest.raises(psycopg.OperationalError):
        service.login_connect(PASSWORD)
    assert workload_apps[3][1].execute("SELECT score FROM scores").fetchone() == (42,)


@pytest.mark.parametrize("failure", ["baseline", "candidate", "timeout", "revocation", "old-still-works"])
def test_failed_verification_never_leaves_login_open(workload_apps, failure):
    service, baseline = verifier(workload_apps)
    guard = lambda: None
    candidate = PASSWORD
    if failure == "baseline":
        baseline = "sha256:" + "f" * 64
    if failure == "candidate":
        candidate = "wrong-candidate-at-least-32-characters"
    if failure == "timeout":
        service.login_connect = Mock(side_effect=psycopg.OperationalError("timeout"))
    if failure == "old-still-works":
        real = service.login_connect
        service.login_connect = lambda _: real(PASSWORD)
    if failure == "revocation":

        def guard():
            observed = service.restriction.inspect(guard=lambda: None)
            if observed["login_enabled"]:
                raise PermissionError("revoked")

    with pytest.raises((ValueError, psycopg.OperationalError, PermissionError)):
        service.verify(
            candidate_password=candidate,
            previous_password="disposable-only",
            expected_fingerprint=baseline,
            guard=guard,
        )
    final = service.restriction.inspect(guard=lambda: None)
    assert final["login_enabled"] is False and final["active_sessions"] == 0
