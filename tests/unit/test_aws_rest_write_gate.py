from copy import deepcopy
from unittest.mock import Mock

import pytest

from adapters.aws.rest_write_gate import AwsRestWriteGate

ACCOUNT = "123456789012"
REGION = "ap-northeast-2"
ALB = f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/owned/1234567890abcdef"


@pytest.fixture
def gate():
    left = {
        "application_id": "app",
        "organization_id": "org",
        "account_id": ACCOUNT,
        "region": REGION,
        "role": "shared_workload",
    }
    right = {**left, "role": "dedicated_workload"}
    waf, elb, sts = Mock(), Mock(), Mock()
    hosts = [f"{c}.ecs.{REGION}.on.aws" for c in ("blue", "green")]
    instance = AwsRestWriteGate(
        account_id=ACCOUNT,
        region=REGION,
        application_id="app",
        organization_id="org",
        acl_id="a" * 8 + "-" + "a" * 4 + "-" + "a" * 4 + "-" + "a" * 4 + "-" + "a" * 12,
        acl_name="sky-rest-gate-unit",
        marker="b" * 32,
        hosts=hosts,
        bindings=[left, right],
        load_balancers=[ALB],
        waf=waf,
        elb=elb,
        sts=sts,
        guard=Mock(),
        probe=Mock(),
        contract={
            "schema_version": 1,
            "read_only_methods": ["GET", "HEAD", "OPTIONS"],
            "http_only_writers": True,
            "all_database_writers_registered": True,
        },
    )
    sts.get_caller_identity.return_value = {"Account": ACCOUNT}
    elb.describe_load_balancers.return_value = {
        "LoadBalancers": [{"LoadBalancerArn": ALB, "Type": "application"}]
    }
    elb.describe_listeners.return_value = {
        "Listeners": [{"ListenerArn": "listener", "Protocol": "HTTPS", "Port": 443}]
    }
    rules = [
        {
            "IsDefault": True,
            "Actions": [{"Type": "fixed-response", "FixedResponseConfig": {"StatusCode": "404"}}],
        }
    ]
    rules += [
        {
            "IsDefault": False,
            "Conditions": [{"Field": "host-header", "Values": [h]}],
            "Actions": [{"Type": "forward"}],
        }
        for h in hosts
    ]
    elb.describe_rules.return_value = {"Rules": rules}
    state = {
        "Rules": instance.rules(hosts[0], instance.marker),
        "ARN": instance.arn,
        "DefaultAction": {"Allow": {}},
        "VisibilityConfig": {},
    }
    waf.get_web_acl.side_effect = lambda **_: {"WebACL": deepcopy(state), "LockToken": "version"}
    waf.get_web_acl_for_resource.return_value = {"WebACL": {"ARN": instance.arn}}
    tags = {
        "sky-managed": "true",
        "sky-application": "app",
        "sky-organization": "org",
        "sky-write-gate": instance.marker,
    }
    waf.list_tags_for_resource.return_value = {
        "TagInfoForResource": {"TagList": [{"Key": k, "Value": v} for k, v in tags.items()]}
    }

    def update(**kwargs):
        state["Rules"] = kwargs["Rules"]

    waf.update_web_acl.side_effect = update
    return instance, waf, elb, state


def test_close_and_open_only_registered_writer(gate):
    instance, waf, _, _ = gate
    assert instance.set_active(None)["http_writes_blocked"]
    instance.probe.assert_called_once_with(None, instance.marker)
    assert instance.set_active(instance.bindings[1])["active_binding"] == instance.bindings[1]
    assert waf.update_web_acl.call_count == 2
    assert waf.update_web_acl.call_args.kwargs["LockToken"] == "version"


@pytest.mark.parametrize(
    "fault", ["other_app", "default_route", "wrong_account", "wrong_association", "pagination"]
)
def test_fail_closed_before_any_acl_update(gate, fault):
    instance, waf, elb, _ = gate
    if fault == "other_app":
        elb.describe_rules.return_value["Rules"][1]["Conditions"][0]["Values"] = ["other.example"]
    elif fault == "default_route":
        elb.describe_rules.return_value["Rules"][0]["Actions"] = [{"Type": "forward"}]
    elif fault == "wrong_account":
        instance.balancers = [ALB.replace(ACCOUNT, "999999999999")]
    elif fault == "wrong_association":
        waf.get_web_acl_for_resource.return_value = {"WebACL": {"ARN": "other"}}
    else:
        elb.describe_rules.return_value["NextMarker"] = "more"
    with pytest.raises(ValueError):
        instance.set_active(None)
    waf.update_web_acl.assert_not_called()


def test_timeout_never_resubmits_uncertain_update(gate):
    instance, waf, _, _ = gate
    waf.update_web_acl.side_effect = TimeoutError("response lost")
    with pytest.raises(TimeoutError):
        instance.set_active(None)
    with pytest.raises(RuntimeError):
        instance.set_active(None)
    assert waf.update_web_acl.call_count == 1


def test_live_probe_required_before_claiming_closed(gate):
    instance, _waf, _, _ = gate
    instance.probe.side_effect = OSError("standby still accepting writes")
    with pytest.raises(OSError):
        instance.set_active(None)
    assert instance.uncertain
    with pytest.raises(RuntimeError):
        instance.set_active(None)
