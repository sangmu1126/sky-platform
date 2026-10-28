"""Actual PostgreSQL atomic admission bounds, not a pricing or billing test."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from adapters.state.admission_limits import AdmissionLimitExceeded, AdmissionLimits
from tests.contract.test_deployment_admission import admit, artifact
from tests.contract.test_deployment_preparation import database as database  # noqa: PLC0414
from tests.contract.test_deployment_preparation import http, principal, request, upload_headers
from tests.contract.test_deployment_preparation import service as service  # noqa: PLC0414
from tests.contract.test_deployment_preparation import upload as upload  # noqa: PLC0414


def test_parallel_previews_cannot_exceed_user_budget(service, upload, database):
    service.previews.admission.limits = AdmissionLimits(user_previews=2, organization_previews=3)
    raw = upload()

    def attempt(index):
        try:
            service.prepare(principal(), f"app{index}", f"request{index}", raw)
            return "accepted"
        except AdmissionLimitExceeded:
            return "limited"

    with ThreadPoolExecutor(max_workers=6) as executor:
        results = list(executor.map(attempt, range(6)))
    assert results.count("accepted") == 2
    assert results.count("limited") == 4
    # Replaying a successful request is still possible when the allowance is exhausted.
    with database() as connection:
        (app,) = connection.execute(
            "SELECT application_id FROM sky_state.deployment_previews WHERE workspace=%s LIMIT 1",
            (service.previews.operations.workspace,),
        ).fetchone()
    result = service.prepare(principal(), app, "request" + app.removeprefix("app"), raw)
    assert result["status"] == "ready"


def test_organization_budget_cannot_be_bypassed_with_another_user(service, upload):
    service.previews.admission.limits = AdmissionLimits(user_previews=1, organization_previews=1)
    raw = upload()
    service.prepare(principal(), "app1", "request1", raw)
    with pytest.raises(AdmissionLimitExceeded):
        service.prepare(principal(user="bob"), "app2", "request2", raw)
    # Different organization has a separate allowance, even for the same actor name.
    service.prepare(principal(org="other"), "app3", "request3", raw)


def test_deployment_admission_counts_once_and_retains_original_idempotency(service):
    store = service.previews.admission
    store.limits = AdmissionLimits(user_deployments=1, organization_deployments=1)
    first = admit(store, key="one", source=artifact(app="first"))
    assert admit(store, key="one", source=artifact(app="first")) == first
    with pytest.raises(AdmissionLimitExceeded):
        admit(store, key="two", source=artifact(app="second"))


@pytest.mark.parametrize("value", [0, -1, True, 10001, 1.5])
def test_limit_configuration_is_bounded(value):
    with pytest.raises(ValueError):
        AdmissionLimits(user_previews=value)


def test_http_reports_admission_limit_without_processing_another_upload(service, database, upload):
    service.previews.admission.limits = AdmissionLimits(user_previews=1, organization_previews=1)
    with http(service, database) as (port, origin, _):
        raw = upload()
        assert request(port, origin, "/api/deployment-previews", raw, upload_headers())[0] == 200
        headers = {**upload_headers(), "Idempotency-Key": "second", "X-Application-Id": "another-app"}
        assert request(port, origin, "/api/deployment-previews", raw, headers)[0] == 429
        assert request(port, origin, "/api/deployment-previews", raw, upload_headers())[0] == 200


def test_operator_policy_rejects_duplicate_or_partial_limits():
    with pytest.raises(ValueError):
        AdmissionLimits.from_environment(
            {"SKY_ADMISSION_LIMITS_JSON": '{"user_previews":1,"user_previews":2}'}
        )
    with pytest.raises(ValueError):
        AdmissionLimits.from_environment({"SKY_ADMISSION_LIMITS_JSON": '{"user_previews":1}'})


def test_active_application_limit_survives_a_new_hour_and_requires_retirement(service, database):
    store = service.previews.admission
    store.limits = AdmissionLimits(user_active_applications=1, organization_active_applications=1)
    first = admit(store, key="one", source=artifact(app="first"))
    # Moving the hourly admission timestamp back must not release active application capacity.
    with database() as connection:
        connection.execute(
            "UPDATE sky_state.operations SET created_at=clock_timestamp()-interval '2 hours' WHERE workspace=%s",
            (store.operations.workspace,),
        )
    with pytest.raises(AdmissionLimitExceeded, match="Active application"):
        admit(store, key="two", source=artifact(app="second"))
    assert admit(store, key="one", source=artifact(app="first")) == first
    snapshot = store.operations.records.load_job(first.job_id)
    store.operations.records.save_job(
        first.job_id, {**snapshot.record, "deployment_state": "deleted"}, expected_revision=snapshot.revision
    )
    # The test simulates a trusted retirement receipt; it does not delete AWS resources.
    assert admit(store, key="two", source=artifact(app="second")).job_id != first.job_id
