"""Operator-owned VM registration; source/model data cannot widen the boundary."""

import ipaddress
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SandboxProfile:
    name: str
    account_id: str
    region: str
    vpc_id: str
    subnet_id: str
    security_group_id: str
    operator_cidr: str
    scheduler_role_arn: str
    scheduler_group: str
    reaper_arn: str
    ami_id: str
    ami_owner: str
    max_lifetime_seconds: int = 900

    def __post_init__(self):
        patterns = {
            "name": r"sky-[a-z0-9-]{1,28}",
            "account_id": r"[0-9]{12}",
            "region": r"[a-z]{2}(?:-[a-z]+)+-\d+",
            "vpc_id": r"vpc-[0-9a-f]{8,17}",
            "subnet_id": r"subnet-[0-9a-f]{8,17}",
            "security_group_id": r"sg-[0-9a-f]{8,17}",
            "ami_id": r"ami-[0-9a-f]{8,17}",
            "ami_owner": r"[0-9]{12}",
            "scheduler_group": r"sky-[a-z0-9-]{1,28}",
        }
        if any(
            not isinstance(getattr(self, field), str) or not re.fullmatch(pattern, getattr(self, field))
            for field, pattern in patterns.items()
        ):
            raise ValueError("Exact registered sandbox identities required")
        network = ipaddress.ip_network(self.operator_cidr, strict=True)
        if network.version != 4 or network.prefixlen != 32 or not network.network_address.is_global:
            raise ValueError("A single public operator IPv4 address is required")
        if (
            type(self.max_lifetime_seconds) is not int
            or not 180 <= self.max_lifetime_seconds <= 1800
            or not re.fullmatch(
                f"arn:aws:iam::{self.account_id}:role/sky-[a-z0-9-]+", self.scheduler_role_arn
            )
            or not re.fullmatch(
                f"arn:aws:lambda:{self.region}:{self.account_id}:function:sky-[a-z0-9-]+", self.reaper_arn
            )
        ):
            raise ValueError("Registered account-scoped deadline and bounded lifetime required")

    def verify_network(self, ec2):
        groups = ec2.describe_security_groups(GroupIds=[self.security_group_id])["SecurityGroups"]
        if len(groups) != 1:
            raise ValueError("Exactly one isolated security group required")
        group = groups[0]
        if (
            group.get("VpcId") != self.vpc_id
            or group.get("OwnerId") != self.account_id
            or group.get("IpPermissionsEgress") != []
            or {t["Key"]: t["Value"] for t in group.get("Tags", [])}.get("sky:SandboxProfile") != self.name
        ):
            raise ValueError("Sandbox must have no outbound security group rules")
        expected = [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": self.operator_cidr}],
                "Ipv6Ranges": [],
                "UserIdGroupPairs": [],
                "PrefixListIds": [],
            }
        ]

        # Descriptions are display metadata, not permissions.
        def normalized(rules):
            return [
                {
                    k: (
                        [{a: b for a, b in item.items() if a != "Description"} for item in v]
                        if isinstance(v, list)
                        else v
                    )
                    for k, v in rule.items()
                }
                for rule in rules
            ]

        if normalized(group.get("IpPermissions", [])) != expected:
            raise ValueError("Sandbox ingress must be operator SSH only")
        subnet = ec2.describe_subnets(SubnetIds=[self.subnet_id])["Subnets"]
        if len(subnet) != 1 or subnet[0]["VpcId"] != self.vpc_id or subnet[0]["OwnerId"] != self.account_id:
            raise ValueError("Sandbox subnet registration differs")
        vpc = ec2.describe_vpcs(VpcIds=[self.vpc_id])["Vpcs"]
        if (
            len(vpc) != 1
            or vpc[0]["OwnerId"] != self.account_id
            or {t["Key"]: t["Value"] for t in vpc[0].get("Tags", [])}.get("sky:SandboxProfile") != self.name
        ):
            raise ValueError("Dedicated sandbox VPC registration differs")
        images = ec2.describe_images(ImageIds=[self.ami_id], Owners=[self.ami_owner])["Images"]
        if (
            len(images) != 1
            or images[0].get("State") != "available"
            or images[0].get("Architecture") != "x86_64"
            or not images[0].get("Name", "").startswith("al2023-ami-ecs-hvm-")
        ):
            raise ValueError("Pinned trusted ECS-optimized AMI required")
