"""Operator opt-in for trusted owners using an already registered workload pool.

No credentials, SQL or cloud calls occur in the API. Application requirements
remain in the approved plan; execution must discharge them before deployment.
Untrusted owners and unsupported resource combinations remain blocked.
"""

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime

POSTGRES_ENVIRONMENT = frozenset(
    {"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGSSLMODE", "PGSSLROOTCERT"}
)


@dataclass(frozen=True)
class DatabaseBuildPolicy:
    account_id: str
    region: str
    organization_id: str
    allowed_users: tuple[str, ...]
    pool_id: str
    instance_id: str
    configuration_digest: str
    expires_at: str

    def __post_init__(self):
        if (
            not re.fullmatch(r"[0-9]{12}", self.account_id)
            or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d+", self.region)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", self.organization_id)
            or not isinstance(self.allowed_users, tuple)
            or not 1 <= len(self.allowed_users) <= 32
            or any(
                not isinstance(x, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", x)
                for x in self.allowed_users
            )
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,30}", self.pool_id)
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", self.instance_id)
            or not re.fullmatch(r"[0-9a-f]{64}", self.configuration_digest)
            or datetime.fromisoformat(self.expires_at).tzinfo is None
        ):
            raise ValueError("Exact trusted-owner/pool database policy required")

    @classmethod
    def load(cls, text):
        if not isinstance(text, str) or len(text) > 8192:
            raise ValueError("Bounded operator database build policy required")
        d = json.loads(text)
        if not isinstance(d, dict) or d.pop("version", None) != 1:
            raise ValueError("Unsupported database build policy")
        d["allowed_users"] = tuple(d.get("allowed_users", []))
        return cls(**d)

    def binding(self):
        return {
            k: getattr(self, k)
            for k in ("account_id", "region", "pool_id", "instance_id", "configuration_digest", "expires_at")
        }

    def apply(self, principal, plan, inspection, blockers, *, now=None):
        now = now or datetime.now(UTC)
        requirements = set(inspection["requirements"])
        if not requirements:
            return blockers
        if (
            now >= datetime.fromisoformat(self.expires_at)
            or principal.organization_id != self.organization_id
            or principal.user_id not in self.allowed_users
        ):
            return blockers
        if requirements != {"database"} or inspection["database_engines"] != ["postgresql"]:
            return blockers
        if set(plan["required_env"]) - POSTGRES_ENVIRONMENT:
            return blockers
        plan["database_profile"] = "shared-postgres-v1"
        plan["database_pool_registration"] = self.binding()
        plan["infrastructure_profile"] = {
            "requirements": sorted(requirements),
            "database_engines": ["postgresql"],
        }
        return [
            b
            for b in blockers
            if b["code"] not in {"infrastructure_preparation_required", "environment_binding_required"}
        ]

    def authorize(self, request, artifact, plan, *, now=None):
        now = now or datetime.now(UTC)
        if (
            now >= datetime.fromisoformat(self.expires_at)
            or artifact.organization_id != self.organization_id
            or request["created_by"] not in self.allowed_users
            or plan.get("database_pool_registration") != self.binding()
            or (request["account_id"], request["region"]) != (self.account_id, self.region)
            or plan.get("database_profile") != "shared-postgres-v1"
            or plan.get("infrastructure_profile")
            != {"requirements": ["database"], "database_engines": ["postgresql"]}
            or set(plan.get("required_env", [])) - POSTGRES_ENVIRONMENT
        ):
            raise PermissionError("Database build differs from current trusted owner/pool approval")
