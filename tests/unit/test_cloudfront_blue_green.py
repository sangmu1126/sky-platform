from copy import deepcopy
from unittest.mock import Mock

import pytest

from adapters.aws.cloudfront_blue_green import AwsCloudFrontBlueGreenRouter


@pytest.fixture
def router():
    account = "123456789012"
    region = "ap-northeast-2"
    identifier = "E1234567890"
    revision = "sha256:" + "a" * 64
    source = {
        "organization_id": "org",
        "application_id": "app",
        "account_id": account,
        "region": region,
        "role": "shared_workload",
        "instance_id": "shared",
        "database_name": "appdb",
        "owner_ref": "allocation",
    }
    target = {**source, "role": "dedicated_workload", "instance_id": "dedicated"}
    hosts = [f"{colour}.ecs.{region}.on.aws" for colour in ["blue", "green"]]
    origins = [
        {
            "Id": "sky-" + colour,
            "DomainName": host,
            "CustomOriginConfig": {
                "OriginProtocolPolicy": "https-only",
                "HTTPSPort": 443,
                "OriginSslProtocols": {"Items": ["TLSv1.2"]},
            },
        }
        for colour, host in zip(["blue", "green"], hosts)
    ]
    behavior = {
        "TargetOriginId": "sky-blue",
        "ViewerProtocolPolicy": "https-only",
        "AllowedMethods": {"Items": ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]},
        "CachePolicyId": "disabled",
        "OriginRequestPolicyId": "all-except-host",
    }
    config = {
        "CallerReference": "sky-bg-unit",
        "Enabled": True,
        "Aliases": {"Quantity": 0},
        "Origins": {"Quantity": 2, "Items": origins},
        "ViewerCertificate": {"CloudFrontDefaultCertificate": True},
        "DefaultCacheBehavior": behavior,
    }
    arn = f"arn:aws:cloudfront::{account}:distribution/{identifier}"
    value = {
        "ETag": "v1",
        "Distribution": {
            "ARN": arn,
            "Id": identifier,
            "DomainName": "unit.cloudfront.net",
            "Status": "Deployed",
            "DistributionConfig": config,
        },
    }
    client = Mock()
    sts = Mock()
    sts.get_caller_identity.return_value = {"Account": account}
    client.get_distribution.side_effect = lambda **_: deepcopy(value)
    tags = {
        "sky-managed": "true",
        "sky-application": "app",
        "sky-organization": "org",
        "sky-traffic-controller": "cloudfront-blue-green-v1",
    }
    client.list_tags_for_resource.return_value = {
        "Tags": {"Items": [{"Key": k, "Value": v} for k, v in tags.items()]}
    }
    client.get_cache_policy.return_value = {
        "CachePolicy": {"CachePolicyConfig": {"MinTTL": 0, "DefaultTTL": 0, "MaxTTL": 0}}
    }
    client.get_origin_request_policy.return_value = {
        "OriginRequestPolicy": {
            "OriginRequestPolicyConfig": {
                "HeadersConfig": {
                    "HeaderBehavior": "allExcept",
                    "Headers": {"Quantity": 1, "Items": ["host"]},
                },
                "CookiesConfig": {"CookieBehavior": "all"},
                "QueryStringsConfig": {"QueryStringBehavior": "all"},
            }
        }
    }

    def update(**kw):
        assert kw["IfMatch"] == "v1"
        value["Distribution"]["DistributionConfig"] = deepcopy(kw["DistributionConfig"])

    client.update_distribution.side_effect = update
    probe = Mock(
        side_effect=lambda _: {
            "binding": target
            if value["Distribution"]["DistributionConfig"]["DefaultCacheBehavior"]["TargetOriginId"]
            == "sky-green"
            else source,
            "revision": revision,
            "database_read_verified": True,
        }
    )
    instance = AwsCloudFrontBlueGreenRouter(
        account_id=account,
        application_id="app",
        organization_id="org",
        distribution_id=identifier,
        caller_reference="sky-bg-unit",
        source=source,
        target=target,
        blue_host=hosts[0],
        green_host=hosts[1],
        blue_revision=revision,
        green_revision=revision,
        client=client,
        sts=sts,
        guard=Mock(),
        entrypoint_probe=probe,
        wait=lambda _: None,
        timeout=1,
    )
    return instance, client, value, probe, source, target


def test_same_url_forward_reverse_verify_real_binding_and_revision(router):
    instance, client, _, probe, source, target = router
    assert instance.current() == source
    assert instance.switch(source, target)["stable_url"] == "https://unit.cloudfront.net"
    assert instance.current() == target
    instance.switch(target, source)
    assert instance.current() == source
    assert probe.call_count == 6
    assert client.update_distribution.call_count == 2


@pytest.mark.parametrize(
    "fault", ["cache", "origin_host", "other_alias", "cookie", "query", "identity", "revision", "read"]
)
def test_unsafe_configuration_or_probe_never_claims_verified_route(router, fault):
    instance, client, value, probe, source, target = router
    if fault == "cache":
        client.get_cache_policy.return_value["CachePolicy"]["CachePolicyConfig"]["MaxTTL"] = 30
    elif fault == "origin_host":
        value["Distribution"]["DistributionConfig"]["Origins"]["Items"][1]["DomainName"] = "attacker.example"
    elif fault == "other_alias":
        value["Distribution"]["DistributionConfig"]["Aliases"] = {"Quantity": 1, "Items": ["other.example"]}
    elif fault in {"cookie", "query"}:
        key = "CookiesConfig" if fault == "cookie" else "QueryStringsConfig"
        client.get_origin_request_policy.return_value["OriginRequestPolicy"]["OriginRequestPolicyConfig"][
            key
        ] = {}
    else:
        observed = {"binding": target, "revision": "sha256:" + "a" * 64, "database_read_verified": True}
        observed[{"identity": "binding", "revision": "revision", "read": "database_read_verified"}[fault]] = (
            None
        )
        probe.side_effect = None
        probe.return_value = observed
    with pytest.raises(ValueError):
        instance.switch(source, target)
    if fault not in {"identity", "revision", "read"}:
        client.update_distribution.assert_not_called()
    else:
        assert instance.uncertain


def test_lost_update_response_is_not_replayed(router):
    instance, client, _, _, source, target = router
    client.update_distribution.side_effect = TimeoutError("Response lost")
    with pytest.raises(TimeoutError):
        instance.switch(source, target)
    with pytest.raises(RuntimeError):
        instance.current()
    with pytest.raises(ValueError):
        instance.switch(source, target)
    assert client.update_distribution.call_count == 1


def test_read_only_resume_after_lost_observation_never_updates_again(router):
    instance, client, value, _probe, _source, target = router
    value["Distribution"]["DistributionConfig"]["DefaultCacheBehavior"]["TargetOriginId"] = "sky-green"
    instance.uncertain = True
    result = instance.observe_switch(target)
    assert result["observation_only"]
    assert instance.current() == target
    client.update_distribution.assert_not_called()


def test_reconciliation_refuses_wrong_route_without_replaying_switch(router):
    instance, client, _value, _probe, _source, target = router
    with pytest.raises(ValueError):
        instance.observe_switch(target)
    assert instance.uncertain
    client.update_distribution.assert_not_called()
