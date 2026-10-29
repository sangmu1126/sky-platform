"""Serialize hourly hosted admission limits inside the owning transaction.

Counts durable admissions, including failed work. No refund and no price estimate.
Existing idempotency keys consume no additional allowance. State retention must
keep the preceding hour; callers cannot supply timestamps, identities or counts.
"""

import hashlib
import json
from dataclasses import dataclass


class AdmissionLimitExceeded(ValueError):
    pass


@dataclass(frozen=True)
class AdmissionLimits:
    user_previews: int = 30
    organization_previews: int = 120
    user_deployments: int = 10
    organization_deployments: int = 40
    user_active_applications: int = 5
    organization_active_applications: int = 20
    global_previews: int = 300
    global_deployments: int = 100
    global_active_applications: int = 100

    def __post_init__(self):
        for value in (
            self.user_previews,
            self.organization_previews,
            self.user_deployments,
            self.organization_deployments,
            self.user_active_applications,
            self.organization_active_applications,
            self.global_previews,
            self.global_deployments,
            self.global_active_applications,
        ):
            if type(value) is not int or not 1 <= value <= 10000:
                raise ValueError("Bounded admission limits required")
        if (
            self.user_previews > self.organization_previews
            or self.user_deployments > self.organization_deployments
            or self.user_active_applications > self.organization_active_applications
        ):
            raise ValueError("User limits cannot exceed organization limits")

    @classmethod
    def from_environment(cls, environment):
        raw = environment.get("SKY_ADMISSION_LIMITS_JSON")
        if raw is None:
            return cls()
        if not isinstance(raw, str) or len(raw) > 1024:
            raise ValueError("Bounded operator admission policy required")

        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("Duplicate admission policy field")
                value[key] = item
            return value

        config = json.loads(raw, object_pairs_hook=unique)
        legacy = {
            "user_previews",
            "organization_previews",
            "user_deployments",
            "organization_deployments",
            "user_active_applications",
            "organization_active_applications",
        }
        expanded = legacy | {"global_previews", "global_deployments", "global_active_applications"}
        if not isinstance(config, dict) or set(config) not in (legacy, expanded):
            raise ValueError("Exact operator admission policy required")
        return cls(**config)

    def check(self, connection, *, workspace, principal, key, kind, application_id=None):
        if connection.execute("SHOW transaction_isolation").fetchone() != ("read committed",):
            raise ValueError("Admission limits require a read-committed transaction")
        lock = int.from_bytes(
            hashlib.sha256(("admission-limit:" + workspace).encode()).digest()[:8], "big", signed=True
        )
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (lock,))
        if kind == "preview":
            existing = connection.execute(
                "SELECT 1 FROM sky_state.deployment_previews WHERE workspace=%s AND request_key=%s",
                (workspace, key),
            ).fetchone()
            if existing:
                return
            global_count = connection.execute(
                "SELECT count(*) FROM sky_state.deployment_previews WHERE workspace=%s "
                "AND created_at > clock_timestamp()-interval '1 hour'",
                (workspace,),
            ).fetchone()[0]
            if global_count >= self.global_previews:
                raise AdmissionLimitExceeded("Global hourly preview limit reached")
            counts = connection.execute(
                """SELECT count(*),count(*) FILTER(WHERE created_by=%s)
                FROM sky_state.deployment_previews WHERE workspace=%s AND organization_id=%s
                AND created_at > clock_timestamp()-interval '1 hour'""",
                (principal.user_id, workspace, principal.organization_id),
            ).fetchone()
            user, organization = self.user_previews, self.organization_previews
        elif kind == "deployment":
            existing = connection.execute(
                "SELECT 1 FROM sky_state.operations WHERE workspace=%s AND request_key=%s",
                (workspace, key),
            ).fetchone()
            if existing:
                return
            if not isinstance(application_id, str) or not application_id:
                raise ValueError("Deployment application identity required")
            active = connection.execute(
                """SELECT count(DISTINCT coalesce(document->>'application_id',record_id)),
                count(DISTINCT coalesce(document->>'application_id',record_id))
                    FILTER(WHERE document->>'created_by'=%s),
                coalesce(bool_or(coalesce(document->>'application_id',record_id)=%s),false)
                FROM sky_state.metadata_records WHERE workspace=%s AND kind='job'
                AND document->>'organization_id'=%s
                AND coalesce(document->>'deployment_state','active')<>'deleted'""",
                (principal.user_id, application_id, workspace, principal.organization_id),
            ).fetchone()
            if not active[2] and (
                active[0] >= self.organization_active_applications
                or active[1] >= self.user_active_applications
            ):
                raise AdmissionLimitExceeded(
                    "Active application limit reached; confirm retirement before new work"
                )
            global_active = connection.execute(
                """SELECT count(DISTINCT (document->>'organization_id',
                    coalesce(document->>'application_id',record_id))) FROM sky_state.metadata_records
                    WHERE workspace=%s AND kind='job' AND coalesce(document->>'deployment_state','active')<>'deleted'""",
                (workspace,),
            ).fetchone()[0]
            if not active[2] and global_active >= self.global_active_applications:
                raise AdmissionLimitExceeded("Global active application limit reached")
            global_count = connection.execute(
                "SELECT count(*) FROM sky_state.operations WHERE workspace=%s AND kind='deploy' "
                "AND created_at > clock_timestamp()-interval '1 hour'",
                (workspace,),
            ).fetchone()[0]
            if global_count >= self.global_deployments:
                raise AdmissionLimitExceeded("Global hourly deployment limit reached")
            counts = connection.execute(
                """SELECT count(*),count(*) FILTER(WHERE command->>'created_by'=%s)
                FROM sky_state.operations WHERE workspace=%s AND kind='deploy'
                AND command->>'organization_id'=%s
                AND created_at > clock_timestamp()-interval '1 hour'""",
                (principal.user_id, workspace, principal.organization_id),
            ).fetchone()
            user, organization = self.user_deployments, self.organization_deployments
        else:
            raise ValueError("Unknown admission kind")
        if counts[0] >= organization or counts[1] >= user:
            raise AdmissionLimitExceeded(
                "Hourly admission limit reached; inspect existing work before retrying"
            )
