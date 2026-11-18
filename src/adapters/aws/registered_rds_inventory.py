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
        clients = ((sts, "sts", "get_caller_identity"), (rds, "rds", "describe_db_instances"))
        if any(
            not callable(getattr(client, operation, None))
            or getattr(getattr(client, "meta", None), "region_name", None) != region
            or getattr(getattr(client, "meta", None), "endpoint_url", None)
            != f"https://{service}.{region}.amazonaws.com"
            for client, service, operation in clients
        ):
            raise ValueError("Regional AWS RDS evidence authority required")
        self.registration, self.sts, self.rds, self.clock = registration, sts, rds, clock

    def verify(self, placement):
        r = self.registration
        if placement != r.placement:
            raise ValueError("RDS placement differs from registration")
        try:
            account = placement.location.authority_ref
            region = placement.location.location
            if self.sts.get_caller_identity()["Account"] != account or self.rds.meta.region_name != region:
                raise ValueError("AWS caller or region changed")
            (value,) = self.rds.describe_db_instances(DBInstanceIdentifier=placement.instance_id)[
                "DBInstances"
            ]
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
                    for item in raw_tags
                )
            ):
                raise ValueError("Canonical RDS ownership tags required")
            tags = {item["Key"]: item["Value"] for item in raw_tags}
            if len(tags) != len(raw_tags):
                raise ValueError("Canonical RDS ownership tags required")
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
                or value.get("DBSubnetGroup", {}).get("VpcId") != r.vpc_id
                or int(value.get("EngineVersion", "0").split(".")[0]) != placement.postgres_major
                or (value.get("Endpoint", {}).get("Address"), value.get("Endpoint", {}).get("Port"))
                != (r.hostname, r.port)
                or sorted(v["VpcSecurityGroupId"] for v in value.get("VpcSecurityGroups", []))
                != sorted(r.security_groups)
                or any(v.get("Status") != "active" for v in value.get("VpcSecurityGroups", []))
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
