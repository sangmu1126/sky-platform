from copy import deepcopy

import pytest

from adapters.aws.incident_recovery import normalized_container


def approved():
    return {
        "name": "App",
        "image": "registered@sha256:" + "a" * 64,
        "user": "65534:65534",
        "privileged": False,
        "readonlyRootFilesystem": True,
        "environment": [{"name": "PORT", "value": "8080"}, {"name": "PGSSLMODE", "value": "verify-full"}],
        "secrets": [
            {"name": "PGUSER", "valueFrom": "registered-username"},
            {"name": "PGPASSWORD", "valueFrom": "registered-password"},
        ],
        "linuxParameters": {"capabilities": {"drop": ["ALL"]}},
    }


def test_actual_ecs_defaults_and_environment_reordering_preserve_configuration():
    plan = approved()
    actual = deepcopy(plan)
    actual.update(cpu=0, mountPoints=[], volumesFrom=[], systemControls=[])
    actual["environment"].reverse()
    actual["secrets"].reverse()
    actual["linuxParameters"]["capabilities"]["add"] = []
    assert normalized_container(actual) == normalized_container(plan)
    assert "cpu" in actual  # input inspection receipt must not be mutated


@pytest.mark.parametrize(
    "change", ["root", "privileged", "capability", "mount", "secret", "network", "entrypoint"]
)
def test_execution_or_credential_changes_are_never_normalized_away(change):
    plan = approved()
    actual = deepcopy(plan)
    if change == "root":
        actual["user"] = "0:0"
    if change == "privileged":
        actual["privileged"] = True
    if change == "capability":
        actual["linuxParameters"]["capabilities"]["add"] = ["SYS_ADMIN"]
    if change == "mount":
        actual["mountPoints"] = [{"sourceVolume": "host", "containerPath": "/host"}]
    if change == "secret":
        actual["secrets"][1]["valueFrom"] = "foreign-secret"
    if change == "network":
        actual["extraHosts"] = [{"hostname": "database", "ipAddress": "192.0.2.1"}]
    if change == "entrypoint":
        actual["entryPoint"] = ["unsafe-entrypoint"]
    assert normalized_container(actual) != normalized_container(plan)


def test_duplicate_secret_names_are_rejected():
    value = approved()
    value["secrets"].append(dict(value["secrets"][0]))
    with pytest.raises(ValueError, match="Unique approved"):
        normalized_container(value)


def test_old_aws_sessions_with_launch_or_unrelated_secret_capabilities_block_recovery():
    from adapters.aws.incident_recovery import old_policy_within_profile

    allowed = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": "owned-app-secret"}
        ],
    }
    assert old_policy_within_profile(allowed, allowed)
    assert old_policy_within_profile({"Version": "2012-10-17", "Statement": []}, allowed)
    for statement in [
        {"Effect": "Allow", "Action": ["ecs:RunTask"], "Resource": "*"},
        {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": "*"},
        {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": "other-app-secret"},
    ]:
        assert not old_policy_within_profile({"Version": "2012-10-17", "Statement": [statement]}, allowed)
