"""Only a current job-tagged temporary role controls hosted disposable VMs."""

from unittest.mock import Mock, patch
from uuid import uuid4

import pytest

from adapters.aws.build_controller_session import controller_session
from tests.unit.test_build_sandbox import profile


def test_hosted_controller_requires_registration_before_any_sts():
    session = Mock()
    with pytest.raises(ValueError):
        controller_session(profile(), session, str(uuid4()), environment={"GITHUB_ACTIONS": "true"})
    session.client.assert_not_called()


def test_role_session_is_short_lived_and_has_only_exact_job_tag():
    session = Mock()
    p = profile()
    job = str(uuid4())
    session.client.return_value.get_caller_identity.return_value = {"Account": p.account_id}
    session.client.return_value.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "synthetic",
            "SecretAccessKey": "synthetic",
            "SessionToken": "synthetic",
        }
    }
    role = f"arn:aws:iam::{p.account_id}:role/sky-security-build-controller"
    with patch("boto3.Session") as scoped:
        controller_session(
            p, session, job, environment={"GITHUB_ACTIONS": "true", "SKY_BUILD_CONTROLLER_ROLE_ARN": role}
        )
    args = session.client.return_value.assume_role.call_args.kwargs
    assert args["DurationSeconds"] == 900 and args["Tags"] == [{"Key": "sky:JobId", "Value": job}]
    assert scoped.call_args.kwargs["aws_session_token"] == "synthetic"
