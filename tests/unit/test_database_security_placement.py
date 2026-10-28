"""Backend availability never overrides explicitly recorded isolation requirements."""

import pytest

from engine.database_placement import select_shared_database
from tests.unit.test_shared_database_workflow import pool, source


@pytest.mark.parametrize(
    "field,value",
    [
        ("data_sensitivity", "high"),
        ("data_sensitivity", "unknown"),
        ("tenant_trust", "untrusted"),
        ("tenant_trust", "unknown"),
        ("physical_isolation_required", True),
    ],
)
def test_shared_database_is_not_allowed_when_explicit_requirements_need_more_isolation(field, value):
    job = source()
    requirements = {
        "data_sensitivity": "low",
        "tenant_trust": "trusted",
        "physical_isolation_required": False,
    }
    requirements[field] = value
    job["database_security_requirements"] = requirements
    with pytest.raises(ValueError, match="isolation"):
        select_shared_database(job, pool(), config_digest="c" * 64)


def test_explicit_low_risk_shared_choice_remains_available():
    job = source()
    job["database_security_requirements"] = {
        "data_sensitivity": "low",
        "tenant_trust": "trusted",
        "physical_isolation_required": False,
    }
    assert select_shared_database(job, pool(), config_digest="c" * 64)["mode"] == "shared_workload"
