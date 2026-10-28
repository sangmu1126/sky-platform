"""Stable managed HTTPS in front of two managed HTTPS application origins.

No domain or Express-managed ALB mutation is needed. CloudFront propagation is
bounded and measured separately from application readiness. ETag fences config
updates, not arbitrary administrators or existing WebSocket connections.
"""

import re
import time
from copy import deepcopy

from domain.database import DatabaseBinding


class AwsCloudFrontBlueGreenRouter:
    def __init__(
        self,
        *,
        account_id,
        application_id,
        organization_id,
        distribution_id,
        caller_reference,
        source,
        target,
        blue_host,
        green_host,
        blue_revision,
        green_revision,
        client,
        sts,
        guard,
        entrypoint_probe,
        wait=time.sleep,
        timeout=1200,
    ):
        left, right = DatabaseBinding(**source), DatabaseBinding(**target)
        if (
            not re.fullmatch(r"[A-Z0-9]{8,32}", distribution_id)
            or left.account_id != account_id
            or right.account_id != account_id
            or left.role != "shared_workload"
            or right.role != "dedicated_workload"
            or left.instance_id == right.instance_id
            or (left.organization_id, left.application_id, left.region)
            != (organization_id, application_id, right.region)
            or (right.organization_id, right.application_id) != (organization_id, application_id)
            or not isinstance(caller_reference, str)
            or not re.fullmatch(r"sky-bg-[A-Za-z0-9_-]{1,128}", caller_reference)
            or any(
                not re.fullmatch(
                    r"[a-z0-9][a-z0-9-]{0,62}\.ecs\." + re.escape(left.region) + r"\.on\.aws", host
                )
                for host in (blue_host, green_host)
            )
            or blue_host == green_host
            or any(not re.fullmatch(r"sha256:[a-f0-9]{64}", x) for x in (blue_revision, green_revision))
            or type(timeout) is not int
            or not 1 <= timeout <= 1800
        ):
            raise ValueError("Exact same-app CloudFront and managed HTTPS origin registration required")
        self.account, self.application, self.organization = account_id, application_id, organization_id
        self.distribution, self.reference = distribution_id, caller_reference
        self.bindings = [deepcopy(source), deepcopy(target)]
        self.hosts, self.revisions = [blue_host, green_host], [blue_revision, green_revision]
        self.client, self.sts, self.guard, self.entrypoint_probe = client, sts, guard, entrypoint_probe
        self.wait, self.timeout, self.uncertain = wait, timeout, False

    def _audit(self, *, pending=False):
        self.guard()
        if self.sts.get_caller_identity().get("Account") != self.account:
            raise ValueError("CloudFront caller account changed")
        value = self.client.get_distribution(Id=self.distribution)
        distribution = value["Distribution"]
        config = distribution["DistributionConfig"]
        arn = f"arn:aws:cloudfront::{self.account}:distribution/{self.distribution}"
        tags = self.client.list_tags_for_resource(Resource=arn)["Tags"].get("Items", [])
        owned = {x["Key"]: x["Value"] for x in tags}
        if (
            distribution.get("ARN") != arn
            or distribution.get("Id") != self.distribution
            or config.get("CallerReference") != self.reference
            or config.get("Enabled") is not True
            or (not pending and distribution.get("Status") != "Deployed")
            or any(
                owned.get(k) != v
                for k, v in {
                    "sky-managed": "true",
                    "sky-application": self.application,
                    "sky-organization": self.organization,
                    "sky-traffic-controller": "cloudfront-blue-green-v1",
                }.items()
            )
            or config.get("Aliases", {}).get("Quantity") != 0
            or config.get("CacheBehaviors", {}).get("Quantity", 0) != 0
            or config.get("OriginGroups", {}).get("Quantity", 0) != 0
            or config.get("ViewerCertificate", {}).get("CloudFrontDefaultCertificate") is not True
            or config.get("DefaultRootObject", "") != ""
        ):
            raise ValueError("Owned exclusive CloudFront HTTPS distribution required")
        origins = config.get("Origins", {}).get("Items", [])
        if config.get("Origins", {}).get("Quantity") != 2 or len(origins) != 2:
            raise ValueError("Exactly two registered origins required")
        for colour, host in zip(("blue", "green"), self.hosts, strict=True):
            matches = [o for o in origins if o.get("Id") == "sky-" + colour]
            if len(matches) != 1:
                raise ValueError("Registered origin identity changed")
            origin = matches[0]
            transport = origin.get("CustomOriginConfig", {})
            if (
                origin.get("DomainName") != host
                or origin.get("OriginPath", "")
                or origin.get("OriginAccessControlId")
                or origin.get("CustomHeaders", {}).get("Quantity", 0) != 0
                or transport.get("OriginProtocolPolicy") != "https-only"
                or transport.get("HTTPSPort") != 443
                or transport.get("OriginSslProtocols", {}).get("Items") != ["TLSv1.2"]
            ):
                raise ValueError("Managed origin HTTPS configuration changed")
        behavior = config["DefaultCacheBehavior"]
        if (
            behavior.get("TargetOriginId") not in {"sky-blue", "sky-green"}
            or behavior.get("ViewerProtocolPolicy") not in {"https-only", "redirect-to-https"}
            or behavior.get("LambdaFunctionAssociations", {}).get("Quantity", 0) != 0
            or behavior.get("FunctionAssociations", {}).get("Quantity", 0) != 0
            or behavior.get("TrustedSigners", {}).get("Enabled", False)
            or behavior.get("TrustedKeyGroups", {}).get("Enabled", False)
            or set(behavior.get("AllowedMethods", {}).get("Items", []))
            != {"GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"}
        ):
            raise ValueError("Exclusive non-rewriting application behavior required")
        policy = self.client.get_cache_policy(Id=behavior["CachePolicyId"])["CachePolicy"][
            "CachePolicyConfig"
        ]
        if any(policy.get(k) != 0 for k in ("MinTTL", "DefaultTTL", "MaxTTL")):
            raise ValueError("Database application responses must not be cached")
        origin_policy = self.client.get_origin_request_policy(Id=behavior["OriginRequestPolicyId"])[
            "OriginRequestPolicy"
        ]["OriginRequestPolicyConfig"]
        if (
            origin_policy.get("HeadersConfig")
            != {"HeaderBehavior": "allExcept", "Headers": {"Quantity": 1, "Items": ["host"]}}
            or origin_policy.get("CookiesConfig") != {"CookieBehavior": "all"}
            or origin_policy.get("QueryStringsConfig") != {"QueryStringBehavior": "all"}
        ):
            raise ValueError("Forward app cookies/query and managed origin Host without rewriting")
        domain = distribution.get("DomainName", "")
        if not re.fullmatch(r"[a-z0-9]+\.cloudfront\.net", domain):
            raise ValueError("Managed HTTPS domain required")
        self.guard()
        return value, "https://" + domain

    def current(self):
        if self.uncertain:
            raise RuntimeError("CloudFront route requires durable reconciliation")
        value, _ = self._audit()
        colour = value["Distribution"]["DistributionConfig"]["DefaultCacheBehavior"]["TargetOriginId"]
        return deepcopy(self.bindings[0 if colour == "sky-blue" else 1])

    def switch(self, expected_binding, target_binding):
        if self.uncertain or expected_binding == target_binding or target_binding not in self.bindings:
            raise ValueError("Exact CloudFront transition required")
        value, _ = self._audit()
        config = deepcopy(value["Distribution"]["DistributionConfig"])
        current = self.bindings[0 if config["DefaultCacheBehavior"]["TargetOriginId"] == "sky-blue" else 1]
        if current != expected_binding:
            raise ValueError("CloudFront current binding changed")
        config["DefaultCacheBehavior"]["TargetOriginId"] = (
            "sky-blue" if target_binding == self.bindings[0] else "sky-green"
        )
        self.guard()
        self.uncertain = True
        self.client.update_distribution(
            Id=self.distribution, IfMatch=value["ETag"], DistributionConfig=config
        )
        end = time.monotonic() + self.timeout
        while time.monotonic() < end:
            observed, url = self._audit(pending=True)
            actual = observed["Distribution"]["DistributionConfig"]
            if actual != config:
                raise ValueError("CloudFront configuration changed during propagation")
            if observed["Distribution"]["Status"] == "Deployed":
                for _ in range(3):
                    self._probe(target_binding, url)
                self.uncertain = False
                return {
                    "strategy": "blue_green",
                    "binding": deepcopy(target_binding),
                    "stable_url": url,
                    "propagation_verified": True,
                    "websocket_sessions_preserved": False,
                }
            self.wait(5)
        raise TimeoutError("CloudFront propagation requires observation; do not resubmit")

    def observe_switch(self, expected_binding):
        """Read-only continuation after the original writer has been fenced.

        The caller owns durable reconciliation and confirms the old executor
        ended. Never send another update for a lost/uncertain response.
        """
        if expected_binding not in self.bindings:
            raise ValueError("Registered expected route required")
        expected = "sky-blue" if expected_binding == self.bindings[0] else "sky-green"
        self.uncertain = True
        end = time.monotonic() + self.timeout
        while time.monotonic() < end:
            value, url = self._audit(pending=True)
            actual = value["Distribution"]["DistributionConfig"]["DefaultCacheBehavior"]["TargetOriginId"]
            if actual != expected:
                raise ValueError("Observed route does not match the unresolved transition")
            if value["Distribution"]["Status"] == "Deployed":
                for _ in range(3):
                    self._probe(expected_binding, url)
                self.uncertain = False
                return {
                    "binding": deepcopy(expected_binding),
                    "stable_url": url,
                    "propagation_verified": True,
                    "observation_only": True,
                }
            self.wait(5)
        raise TimeoutError("Route propagation is still unresolved; no update was repeated")

    def _probe(self, binding, url):
        index = self.bindings.index(binding)
        self.guard()
        result = self.entrypoint_probe(url)
        if (
            not isinstance(result, dict)
            or result.get("binding") != binding
            or result.get("revision") != self.revisions[index]
            or result.get("database_read_verified") is not True
        ):
            raise ValueError("Stable HTTPS endpoint did not verify expected application and database")
        self.guard()
        return {"binding": deepcopy(binding), "revision": result["revision"], "database_read_verified": True}

    def probe(self, expected_binding):
        if self.current() != expected_binding:
            raise ValueError("CloudFront route differs before application probe")
        _, url = self._audit()
        return self._probe(expected_binding, url)
