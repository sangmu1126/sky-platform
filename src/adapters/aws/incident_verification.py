"""Read only the two registered credential versions; never persist secret values."""

import json
from dataclasses import asdict

from adapters.database.incident_verification import PostgresIncidentVerification


class AwsIncidentVerification:
    def __init__(
        self,
        preparation,
        *,
        workload_connect,
        login_connect,
        registration,
        secret_access,
        cleanup_restriction=None,
    ):
        self.preparation, self.registration, self.secret_access = preparation, registration, secret_access
        if preparation.binding != registration.binding or preparation.resource_id != registration.resource_id:
            raise ValueError("Matching registered credential and workload Secret required")
        self.sql = PostgresIncidentVerification(
            preparation.restriction,
            workload_connect=workload_connect,
            login_connect=login_connect,
            cleanup_restriction=cleanup_restriction,
        )

    def verify(self, context, target, *, expected_fingerprint, guard):
        p, registration = self.preparation, self.registration
        if (
            context.get("binding") != asdict(p.binding)
            or context.get("resource_id") != p.resource_id
            or context.get("preparer_principal") != p.principal_arn
            or context.get("secret_arn") != registration.secret_arn
        ):
            raise ValueError("Exact registered credential verification scope required")
        guard()
        observation = self.secret_access.inspect(context, target, guard=guard)
        if (
            observation.get("policy_state") != "runtime_roles_denied"
            or observation.get("candidate_protected") is not True
        ):
            raise ValueError("Registered runtime Secret denial and isolated candidate required")
        version = context["candidate_version_id"]
        observed = p.inspect(version, guard=guard)
        if (
            observed.get("candidate_state") != "registered_candidate"
            or observed.get("candidate_secret_ref") != context["candidate_secret_arn"]
        ):
            raise ValueError("Exact private candidate credential version required")
        guard()
        candidate = p.client.get_secret_value(
            SecretId=context["candidate_secret_arn"], VersionId=version, VersionStage="AWSCURRENT"
        )
        guard()
        previous = p.client.get_secret_value(SecretId=registration.secret_arn, VersionStage="AWSCURRENT")
        guard()
        if (
            candidate.get("ARN") != context["candidate_secret_arn"]
            or candidate.get("VersionId") != version
            or "AWSCURRENT" not in candidate.get("VersionStages", [])
            or previous.get("ARN") != registration.secret_arn
            or "AWSCURRENT" not in previous.get("VersionStages", [])
        ):
            raise ValueError("Registered current credential versions required")
        fresh, old = json.loads(candidate["SecretString"]), json.loads(previous["SecretString"])
        role = p.restriction.fence.role
        if (
            fresh.get("binding") != asdict(p.binding)
            or fresh.get("operation_id") != version
            or fresh.get("resource_id") != p.resource_id
            or fresh.get("sslmode") != "verify-full"
            or fresh.get("username") != role
            or old.get("username") != role
            or old.get("dbname") != p.binding.database_name
            or old.get("resource_id") != p.resource_id
        ):
            raise ValueError("Credential contents differ from registered workload identity")
        result = self.sql.verify(
            candidate_password=fresh["password"],
            previous_password=old["password"],
            expected_fingerprint=expected_fingerprint,
            guard=guard,
        )
        guard()
        # Fail closed if either pointer changed during authentication. No Secret
        # value or password/hash is returned or written to deployment metadata.
        current = p.client.describe_secret(SecretId=context["candidate_secret_arn"])
        old_current = p.client.describe_secret(SecretId=registration.secret_arn)
        guard()
        if (
            current.get("VersionIdsToStages") != {version: ["AWSCURRENT"]}
            or previous["VersionId"] not in old_current.get("VersionIdsToStages", {})
            or "AWSCURRENT" not in old_current["VersionIdsToStages"][previous["VersionId"]]
        ):
            raise ValueError("Credential version pointers changed during verification")
        return {**result, "candidate_version_id": version, "previous_version_id": previous["VersionId"]}
