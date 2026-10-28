"""WAF write gate for an explicitly reviewed HTTP-only application pair.

GET/HEAD/OPTIONS must be read-only and every untrusted writer must use these
registered origins and the fenced DB roles. WebSocket/background/out-of-band
writers are unsupported. This is not a generic gate for arbitrary web apps.
The operator creates the scoped ACL first; this adapter never replaces another
ACL or edits ECS-managed listener rules.
"""

import re


class AwsRestWriteGate:
    def __init__(
        self,
        *,
        account_id,
        region,
        application_id,
        organization_id,
        acl_id,
        acl_name,
        marker,
        hosts,
        bindings,
        load_balancers,
        waf,
        elb,
        sts,
        guard,
        probe,
        contract,
    ):
        if (
            contract
            != {
                "schema_version": 1,
                "read_only_methods": ["GET", "HEAD", "OPTIONS"],
                "http_only_writers": True,
                "all_database_writers_registered": True,
            }
            or not re.fullmatch(r"[a-f0-9-]{36}", acl_id)
            or not re.fullmatch(r"sky-rest-gate-[a-z0-9-]{1,80}", acl_name)
            or not re.fullmatch(r"[a-f0-9]{32}", marker)
            or len(hosts) != 2
            or len(set(hosts)) != 2
            or len(bindings) != 2
            or bindings[0] == bindings[1]
            or any(
                b.get("application_id") != application_id
                or b.get("organization_id") != organization_id
                or b.get("account_id") != account_id
                or b.get("region") != region
                for b in bindings
            )
            or any(
                not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}\.ecs\." + re.escape(region) + r"\.on\.aws", host)
                for host in hosts
            )
        ):
            raise ValueError("Explicit reviewed REST writer contract and owned origin pair required")
        self.account, self.region, self.application, self.organization = (
            account_id,
            region,
            application_id,
            organization_id,
        )
        self.id, self.name, self.marker = acl_id, acl_name, marker
        self.arn = f"arn:aws:wafv2:{region}:{account_id}:regional/webacl/{acl_name}/{acl_id}"
        self.hosts, self.bindings, self.balancers = list(hosts), list(bindings), list(load_balancers)
        self.waf, self.elb, self.sts, self.guard, self.probe = waf, elb, sts, guard, probe
        self.uncertain = False

    @staticmethod
    def rules(active_host, marker):
        def equal(field, value):
            return {
                "ByteMatchStatement": {
                    "FieldToMatch": field,
                    "PositionalConstraint": "EXACTLY",
                    "SearchString": value.encode(),
                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                }
            }

        mutation = {
            "NotStatement": {
                "Statement": {
                    "OrStatement": {
                        "Statements": [equal({"Method": {}}, method) for method in ("GET", "HEAD", "OPTIONS")]
                    }
                }
            }
        }
        statement = (
            mutation
            if active_host is None
            else {
                "AndStatement": {
                    "Statements": [
                        mutation,
                        {
                            "NotStatement": {
                                "Statement": equal({"SingleHeader": {"Name": "host"}}, active_host)
                            }
                        },
                    ]
                }
            }
        )
        return [
            {
                "Name": "BlockUnapprovedWriters",
                "Priority": 0,
                "Statement": statement,
                "Action": {
                    "Block": {
                        "CustomResponse": {
                            "ResponseCode": 503,
                            "ResponseHeaders": [{"Name": "x-sky-write-gate", "Value": marker}],
                        }
                    }
                },
                "VisibilityConfig": {
                    "SampledRequestsEnabled": False,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "SkyRestWriteGate",
                },
            }
        ]

    def _audit_albs(self):
        if not 1 <= len(self.balancers) <= 2 or len(set(self.balancers)) != len(self.balancers):
            raise ValueError("One or two registered managed application ALBs required")
        for arn in self.balancers:
            if not re.fullmatch(
                r"arn:aws:elasticloadbalancing:"
                + re.escape(self.region)
                + ":"
                + re.escape(self.account)
                + r":loadbalancer/app/[A-Za-z0-9-]{1,64}/[a-f0-9]{16}",
                arn,
            ):
                raise ValueError("Registered load balancer account and region required")
            self.guard()
            values = self.elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"]
            if (
                len(values) != 1
                or values[0].get("LoadBalancerArn") != arn
                or values[0].get("Type") != "application"
            ):
                raise ValueError("Registered application load balancer changed")
            listeners = self.elb.describe_listeners(LoadBalancerArn=arn)
            if listeners.get("NextMarker") or len(listeners.get("Listeners", [])) != 1:
                raise ValueError("Exclusive managed HTTPS listener required")
            listener = listeners["Listeners"][0]
            if listener.get("Protocol") != "HTTPS" or listener.get("Port") != 443:
                raise ValueError("Managed origin TLS listener changed")
            rules = self.elb.describe_rules(ListenerArn=listener["ListenerArn"])
            if rules.get("NextMarker"):
                raise ValueError("Incomplete route inventory")
            observed = set()
            default = False
            for rule in rules.get("Rules", []):
                if rule.get("IsDefault"):
                    actions = rule.get("Actions", [])
                    if (
                        len(actions) != 1
                        or actions[0].get("Type") != "fixed-response"
                        or actions[0].get("FixedResponseConfig", {}).get("StatusCode") != "404"
                    ):
                        raise ValueError("Unknown Host must never route to an app")
                    default = True
                    continue
                conditions = rule.get("Conditions", [])
                actions = rule.get("Actions", [])
                if (
                    len(conditions) != 1
                    or conditions[0].get("Field") != "host-header"
                    or len(conditions[0].get("Values", [])) != 1
                    or conditions[0]["Values"][0] not in self.hosts
                    or len(actions) != 1
                    or actions[0].get("Type") != "forward"
                ):
                    raise ValueError("Other apps or nonexclusive routes prevent REST gating")
                observed.add(conditions[0]["Values"][0])
            if not default or not observed:
                raise ValueError("Registered managed origin routing required")

    def _state(self):
        self.guard()
        if self.sts.get_caller_identity().get("Account") != self.account:
            raise ValueError("Write gate caller account changed")
        self._audit_albs()
        result = self.waf.get_web_acl(Name=self.name, Scope="REGIONAL", Id=self.id)
        acl = result["WebACL"]
        owned = {
            x["Key"]: x["Value"]
            for x in self.waf.list_tags_for_resource(ResourceARN=self.arn)["TagInfoForResource"].get(
                "TagList", []
            )
        }
        if (
            acl.get("ARN") != self.arn
            or acl.get("DefaultAction") != {"Allow": {}}
            or acl.get("ManagedByFirewallManager")
            or acl.get("CustomResponseBodies")
            or any(
                owned.get(k) != v
                for k, v in {
                    "sky-managed": "true",
                    "sky-application": self.application,
                    "sky-organization": self.organization,
                    "sky-write-gate": self.marker,
                }.items()
            )
        ):
            raise ValueError("Owned standalone write gate ACL required")
        matched = [host for host in [None, *self.hosts] if acl.get("Rules") == self.rules(host, self.marker)]
        if len(matched) != 1:
            raise ValueError("Write gate rules changed outside the registered contract")
        for arn in self.balancers:
            linked = self.waf.get_web_acl_for_resource(ResourceArn=arn)
            if linked.get("WebACL", {}).get("ARN") != self.arn:
                raise ValueError("Write gate association changed")
        return result, matched[0]

    def set_active(self, binding):
        if self.uncertain:
            raise RuntimeError("Write gate requires durable reconciliation")
        if binding is not None and binding not in self.bindings:
            raise ValueError("Unknown active writer binding")
        active = None if binding is None else self.hosts[self.bindings.index(binding)]
        current, previous = self._state()
        self.guard()
        self.uncertain = True
        acl = current["WebACL"]
        if previous != active:
            self.waf.update_web_acl(
                Name=self.name,
                Scope="REGIONAL",
                Id=self.id,
                DefaultAction={"Allow": {}},
                Rules=self.rules(active, self.marker),
                VisibilityConfig=acl["VisibilityConfig"],
                LockToken=current["LockToken"],
            )
        # The callback checks nonmutating application-specific write probes,
        # including the unique WAF marker, after provider propagation.
        self.probe(active, self.marker)
        _observed, actual = self._state()
        if actual != active:
            raise ValueError("Write gate changed after live verification")
        self.uncertain = False
        return {
            "active_binding": binding,
            "http_writes_blocked": binding is None,
            "protocol": "rest-write-gate-v1",
            "websocket_writers_supported": False,
        }
