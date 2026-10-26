"""Explicit operator registration for a narrow PostgreSQL HTTP recovery runtime."""

import re
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class RecoveryRuntimeRegistration:
    organization_id: str
    application_id: str
    job_id: str
    incident_id: str
    boundary_id: str
    recovery_id: str
    account_id: str
    region: str
    cluster_arn: str
    vpc_id: str
    subnets: tuple[str, ...]
    security_group: str
    execution_role_arn: str
    execution_role_id: str
    task_role_arn: str
    task_role_id: str
    database_host: str
    assign_public_ip: bool = False
    port: int = 8080
    health_path: str = "/health"

    def __post_init__(self):
        for key in ("organization_id", "application_id", "incident_id"):
            if not isinstance(getattr(self, key), str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", getattr(self, key)
            ):
                raise ValueError("Bounded registered recovery scope required")
        if (
            not re.fullmatch(r"[a-f0-9]{16}", self.job_id)
            or any(not re.fullmatch(r"[a-f0-9]{32}", v) for v in (self.boundary_id, self.recovery_id))
            or not re.fullmatch(r"\d{12}", self.account_id)
            or not re.fullmatch(r"[a-z]{2}-[a-z]+-\d", self.region)
        ):
            raise ValueError("Exact recovery account, job and boundary required")
        prefix = f"arn:aws:ecs:{self.region}:{self.account_id}:cluster/sky-"
        if not self.cluster_arn.startswith(prefix) or not re.fullmatch(
            r"[A-Za-z0-9_-]{1,255}", self.cluster_arn.rsplit("/", 1)[-1]
        ):
            raise ValueError("Dedicated registered recovery cluster required")
        if (
            not re.fullmatch(r"vpc-[a-f0-9]{8,17}", self.vpc_id)
            or not re.fullmatch(r"sg-[a-f0-9]{8,17}", self.security_group)
            or not isinstance(self.subnets, tuple)
            or not 1 <= len(self.subnets) <= 3
            or len(set(self.subnets)) != len(self.subnets)
            or any(not re.fullmatch(r"subnet-[a-f0-9]{8,17}", v) for v in self.subnets)
        ):
            raise ValueError("Pinned recovery VPC, subnets and security group required")
        for arn, role_id in [
            (self.execution_role_arn, self.execution_role_id),
            (self.task_role_arn, self.task_role_id),
        ]:
            if not re.fullmatch(
                rf"arn:aws:iam::{self.account_id}:role/sky-recovery-[A-Za-z0-9_-]+", arn
            ) or not re.fullmatch(r"AROA[A-Z0-9]{17}", role_id):
                raise ValueError("Pinned new recovery role incarnations required")
        if self.execution_role_arn == self.task_role_arn or not re.fullmatch(
            rf"[a-z0-9.-]+\.{re.escape(self.region)}\.rds\.amazonaws\.com", self.database_host
        ):
            raise ValueError("Separate execution/task roles and registered RDS endpoint required")
        if (
            type(self.assign_public_ip) is not bool
            or type(self.port) is not int
            or self.port != 8080
            or self.health_path != "/health"
        ):
            raise ValueError("Only the registered PostgreSQL HTTP recovery profile is supported")

    def document(self):
        value = asdict(self)
        value["subnets"] = list(self.subnets)
        return value
