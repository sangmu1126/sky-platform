from copy import deepcopy

import pytest

from adapters.aws.incident_recovery import old_policy_within_profile

STREAM = "arn:aws:logs:ap-northeast-2:123456789012:log-group:/sky/workloads/org/app/0123456789abcdef:log-stream:app/*"
POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["ecr:GetAuthorizationToken"], "Resource": "*"}],
}
LOG = {"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"], "Resource": STREAM}


def test_only_explicit_owned_app_log_stream_is_within_recovery_profile():
    policy = deepcopy(POLICY)
    policy["Statement"].append(LOG)
    assert not old_policy_within_profile(policy, POLICY)
    assert old_policy_within_profile(policy, POLICY, log_stream=STREAM)


@pytest.mark.parametrize(
    "change", ["other_app", "wildcard", "delete", "condition", "other_job", "other_account"]
)
def test_log_exception_cannot_expand_aws_capabilities(change):
    item = deepcopy(LOG)
    if change == "other_app":
        item["Resource"] = STREAM.replace("/org/app/", "/org/other/")
    elif change == "wildcard":
        item["Resource"] = "*"
    elif change == "delete":
        item["Action"] += ["logs:DeleteLogGroup"]
    elif change == "condition":
        item["NotResource"] = "*"
    elif change == "other_job":
        item["Resource"] = STREAM.replace("0123456789abcdef", "fedcba9876543210")
    else:
        item["Resource"] = STREAM.replace("123456789012", "999999999999")
    policy = deepcopy(POLICY)
    policy["Statement"].append(item)
    assert not old_policy_within_profile(policy, POLICY, log_stream=STREAM)


def test_unbounded_registration_is_rejected():
    assert not old_policy_within_profile(POLICY, POLICY, log_stream="*")
