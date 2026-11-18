"""Read-only immutable identity checks for an explicitly registered existing RDS.

This is instance evidence only; logical DB ownership must be composed with the
SQL verifier. It neither adopts pool allocations nor creates resources.
"""

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from domain.database_inventory import DatabaseInventoryUnavailable, DatabaseResourceEvidence
from domain.database_migration import DatabasePlacement


def _regional_rds_authority(sts, rds, region):
    clients = ((sts, "sts", "get_caller_identity"), (rds, "rds", "describe_db_instances"))
    return all(
        callable(getattr(client, operation, None))
        and getattr(getattr(client, "meta", None), "region_name", None) == region
        and getattr(getattr(client, "meta", None), "endpoint_url", None)
        == f"https://{service}.{region}.amazonaws.com"
        for client, service, operation in clients
    )


@dataclass(frozen=True)
class RegisteredRdsInventory:
    placement: DatabasePlacement
    resource_id: str
    hostname: str
    port: int
    vpc_id: str
    security_groups: tuple[str, ...]
    required_tags: tuple[tuple[str, str], ...]

    def __post_init__(self):
        if (
            not isinstance(self.security_groups, tuple)
            or not self.security_groups
            or tuple(sorted(self.security_groups)) != self.security_groups
            or len(set(self.security_groups)) != len(self.security_groups)
            or any(not re.fullmatch(r"sg-[a-f0-9]{8,17}", value) for value in self.security_groups)
        ):
            raise ValueError("Canonical RDS security groups required")
        if (
            not isinstance(self.required_tags, tuple)
            or not self.required_tags
            or any(
                not isinstance(value, tuple)
                or len(value) != 2
                or not all(isinstance(item, str) for item in value)
                or not value[0]
                or not value[1]
                or len(value[0]) > 128
                or len(value[1]) > 256
                for value in self.required_tags
            )
            or tuple(sorted(self.required_tags)) != self.required_tags
            or len(dict(self.required_tags)) != len(self.required_tags)
            or dict(self.required_tags).get("sky-managed") != "true"
        ):
            raise ValueError("Canonical owned RDS tags required")
        if (
            not isinstance(self.placement, DatabasePlacement)
            or self.placement.location.provider != "aws"
            or self.placement.role == "sky_state"
            or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d+", self.placement.location.location)
            or not re.fullmatch(r"db-[A-Za-z0-9]{1,64}", self.resource_id)
            or not re.fullmatch(r"vpc-[a-f0-9]{8,17}", self.vpc_id)
        ):
            raise ValueError("Exact existing workload RDS registration required")
        DatabaseResourceEvidence(self.placement, "registration", datetime.now(UTC), self.hostname, self.port)


class RegisteredRdsInventoryVerifier:
    def __init__(self, registration, *, sts, rds, clock=lambda: datetime.now(UTC)):
        if not isinstance(registration, RegisteredRdsInventory):
            raise TypeError("Typed existing RDS registration required")
        region = registration.placement.location.location
        if not _regional_rds_authority(sts, rds, region):
            raise ValueError("Regional AWS RDS evidence authority required")
        self.registration, self.sts, self.rds, self.clock = registration, sts, rds, clock

    def verify(self, placement):
        r = self.registration
        if placement != r.placement:
            raise ValueError("RDS placement differs from registration")
        try:
            account = placement.location.authority_ref
            region = placement.location.location
            if (
                not _regional_rds_authority(self.sts, self.rds, region)
                or self.sts.get_caller_identity()["Account"] != account
            ):
                raise ValueError("AWS caller or region changed")
            response = self.rds.describe_db_instances(DBInstanceIdentifier=placement.instance_id)
            instances = response.get("DBInstances") if isinstance(response, dict) else None
            if not isinstance(instances, list) or len(instances) != 1 or not isinstance(instances[0], dict):
                raise ValueError("Canonical RDS instance response required")
            value = instances[0]
            arn = f"arn:aws:rds:{region}:{account}:db:{placement.instance_id}"
            raw_tags = value.get("TagList")
            if (
                not isinstance(raw_tags, list)
                or not 1 <= len(raw_tags) <= 50
                or any(
                    not isinstance(item, dict)
                    or set(item) != {"Key", "Value"}
                    or not isinstance(item["Key"], str)
                    or not isinstance(item["Value"], str)
                    or not 1 <= len(item["Key"]) <= 128
                    or len(item["Value"]) > 256
                    for item in raw_tags
                )
            ):
                raise ValueError("Canonical RDS ownership tags required")
            tags = {item["Key"]: item["Value"] for item in raw_tags}
            if len(tags) != len(raw_tags):
                raise ValueError("Canonical RDS ownership tags required")
            engine_version = value.get("EngineVersion")
            subnet = value.get("DBSubnetGroup")
            endpoint = value.get("Endpoint")
            groups = value.get("VpcSecurityGroups")
            if (
                not isinstance(engine_version, str)
                or not re.fullmatch(r"\d+(?:[.]\d+){1,3}", engine_version)
                or not isinstance(subnet, dict)
                or not isinstance(endpoint, dict)
                or not isinstance(groups, list)
                or len(groups) != len(r.security_groups)
                or any(
                    not isinstance(group, dict)
                    or set(group) != {"VpcSecurityGroupId", "Status"}
                    or not isinstance(group["VpcSecurityGroupId"], str)
                    or group["Status"] != "active"
                    for group in groups
                )
            ):
                raise ValueError("Canonical RDS network response required")
            if (
                value.get("DBInstanceArn") != arn
                or value.get("DbiResourceId") != r.resource_id
                # Backing up changes neither resource identity nor tenant
                # ownership. SQL/TLS readiness is a separate mandatory check;
                # backup-related I/O stalls still fail its bounded timeouts.
                or value.get("DBInstanceStatus") not in {"available", "backing-up"}
                or value.get("Engine") != "postgres"
                or value.get("PubliclyAccessible") is not False
                or value.get("StorageEncrypted") is not True
                or subnet.get("VpcId") != r.vpc_id
                or int(engine_version.split(".")[0]) != placement.postgres_major
                or (endpoint.get("Address"), endpoint.get("Port")) != (r.hostname, r.port)
                or tuple(sorted(group["VpcSecurityGroupId"] for group in groups)) != r.security_groups
                or any(tags.get(k) != v for k, v in r.required_tags)
            ):
                raise ValueError("Registered private RDS resource changed")
            digest = hashlib.sha256(
                json.dumps(
                    {
                        "arn": arn,
                        "resource": r.resource_id,
                        "vpc": r.vpc_id,
                        "groups": sorted(r.security_groups),
                        "tags": tags,
                        "observed_status": value.get("DBInstanceStatus"),
                    },
                    sort_keys=True,
                ).encode()
            ).hexdigest()
            return DatabaseResourceEvidence(placement, "RDS-" + digest, self.clock(), r.hostname, r.port)
        except Exception:  # noqa: BLE001 -- redact provider diagnostics
            raise DatabaseInventoryUnavailable("Registered RDS ownership unavailable") from None
