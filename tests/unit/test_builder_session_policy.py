"""Job inputs cannot widen temporary workflow credentials to another app or key."""

from uuid import uuid4

import pytest

from scripts.builder_session_policy import policy


def env():
    job = str(uuid4())
    return {
        "BUILD_ID": job,
        "REQUEST_DIGEST": "a" * 64,
        "REQUEST_KEY": f"sources/team/game/{'b' * 32}/build-requests/{job}.json",
        "SKY_AWS_ACCOUNT_ID": "123456789012",
        "AWS_REGION": "ap-northeast-2",
        "SKY_ARTIFACTS_BUCKET": "sky-test-artifacts",
        "SKY_BUILD_CONTROLLER_ROLE_ARN": "arn:aws:iam::123456789012:role/sky-security-build-controller",
        "SKY_TRUSTED_BUILD_MATERIALS_PREFIX": "trusted-build-materials/" + "c" * 64,
        "SKY_BUILD_SIGNING_KEY_ARN": "arn:aws:kms:ap-northeast-2:123456789012:key/" + str(uuid4()),
    }


@pytest.mark.parametrize("phase", ["prepare", "controller", "publish"])
def test_each_phase_has_only_its_job_and_phase_authority(phase):
    e = env()
    value = policy(phase, e)
    actions = {a for s in value["Statement"] if s["Effect"] == "Allow" for a in s["Action"]}
    assert not actions & {
        "s3:ListBucket",
        "s3:DeleteObject",
        "iam:PassRole",
        "ec2:RunInstances",
        "ecr:GetAuthorizationToken",
    }
    assert "kms:Sign" in actions if phase == "publish" else "kms:Sign" not in actions
    resources = [r for s in value["Statement"] for r in s["Resource"]]
    assert f"arn:aws:s3:::{e['SKY_ARTIFACTS_BUCKET']}/execution-grants/{e['BUILD_ID']}.json" in resources
    assert all(not r.endswith("/builds/*") for r in resources)


@pytest.mark.parametrize(
    "key,value",
    [
        ("REQUEST_KEY", "sources/team/*/x/build-requests/../request.json"),
        ("BUILD_ID", '"},"Action":"*"'),
        ("SKY_ARTIFACTS_BUCKET", "sky-test*"),
        ("SKY_AWS_ACCOUNT_ID", "999999999999*"),
        ("REQUEST_DIGEST", "a" * 63),
    ],
)
def test_adaptive_pointer_widening_is_rejected_before_oidc(key, value):
    e = env()
    e[key] = value
    with pytest.raises(ValueError):
        policy("prepare", e)
