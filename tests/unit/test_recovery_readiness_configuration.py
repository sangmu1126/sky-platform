from types import SimpleNamespace
from unittest.mock import patch

import pytest

from interfaces.recovery_readiness import load_readiness_configuration, native_inspections


def config_args(**kw):
    return SimpleNamespace(
        pool_config=None, dedicated_incident_config=None, incident_secret_config=None, **kw
    )


def test_no_registration_does_not_initialize_cloud_clients_or_database_connections():
    with patch("boto3.Session", side_effect=AssertionError("Unexpected AWS call")):
        configuration = load_readiness_configuration(config_args(), None)
        checks = native_inspections(None, None, configuration, clock=lambda: "", revalidate=lambda: None)
    assert set(checks) == {"runtime", "runtime_containment", "credential_executor", "sky_execution"}


@pytest.mark.parametrize("shared_secret,shared_database", [(True, False), (False, True)])
def test_control_database_or_credentials_cannot_be_registered_as_workload(shared_secret, shared_database):
    secret = "arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:state"
    state = SimpleNamespace(region="ap-northeast-2", secret_arn=secret, database="control")
    pool = SimpleNamespace(
        pool=SimpleNamespace(
            region=state.region,
            account_id="123456789012",
            control_database="control" if shared_database else "pool",
        ),
        admin_secret_arn=secret if shared_secret else secret + "-workload",
    )
    args = config_args()
    args.pool_config = "registration.json"
    with (
        patch("interfaces.recovery_readiness.load_pool_configuration", return_value=(pool, None)),
        pytest.raises(ValueError, match="Separate registered state and workload"),
    ):
        load_readiness_configuration(args, state)


def test_dedicated_registration_requires_explicit_pool_registration():
    args = config_args()
    args.dedicated_incident_config = "dedicated.json"
    with pytest.raises(ValueError, match="requires the workload pool"):
        load_readiness_configuration(args, None)
