"""Database isolation trust is an administrator decision bound to the source."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest

from application.database_security_review import review_database_security
from domain.access import Role
from engine.database_placement import select_shared_database
from tests.unit.test_deployment_writes import ID, Records
from tests.unit.test_shared_database_workflow import actor, pool, source


def test_deployer_cannot_enroll_itself_as_a_trusted_shared_database_tenant():
    records = Records()
    records.job.update(source())
    records.job["id"] = ID
    with pytest.raises(PermissionError):
        review_database_security(
            records,
            actor(),
            ID,
            records.job["database_security_requirements"],
            expected_revision=records.revision,
            review_ref="operator-review",
            now=datetime.now(UTC).isoformat(),
        )
    assert records.save_calls == 0


def test_administrator_can_enroll_exact_source_without_creating_a_database():
    records = Records()
    records.job.update(source())
    records.job["id"] = ID
    records.job.pop("database_security_review")
    assessment = records.job["database_security_requirements"]
    review = review_database_security(
        records,
        actor(Role.ADMIN),
        ID,
        assessment,
        expected_revision=records.revision,
        review_ref="operator-reviewed-owned-app",
        now=datetime.now(UTC).isoformat(),
    )
    assert review["source_digest"] == records.job["source_digest"] and records.save_calls == 1
    choice = select_shared_database(records.job, pool(), config_digest="c" * 64)
    assert choice["security_review_digest"] and choice["deployment_ready"] is False


@pytest.mark.parametrize(
    "change", ["missing", "self-asserted", "stale-source", "stale-assessment", "other-app", "expired"]
)
def test_unknown_or_stale_trust_never_defaults_to_shared_rds(change):
    job = deepcopy(source())
    if change == "missing":
        job.pop("database_security_requirements")
    elif change == "self-asserted":
        job.pop("database_security_review")
    elif change == "stale-source":
        job["source_digest"] = "d" * 64
    elif change == "stale-assessment":
        job["database_security_requirements"]["data_sensitivity"] = "moderate"
    elif change == "other-app":
        job["application_id"] = "foreign"
    else:
        job["database_security_review"]["expires_at"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    with pytest.raises(ValueError):
        select_shared_database(job, pool(), config_digest="c" * 64)
