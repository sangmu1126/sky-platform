"""Read historical consumed approval links; never admit or authorize recovery."""

import json
import re

from domain.access import Principal, Role
from ports.artifacts import SourceArtifact
from ports.remote_builds import canonical, digest, identity, request_for


class PostgresBuildApprovalReader:
    def __init__(self, operations, settings):
        self.operations, self.settings = operations, settings

    def expected_request(self, principal, record):
        if not isinstance(principal, Principal) or principal.role is not Role.ADMIN:
            raise PermissionError("Current organization administrator required")
        if not isinstance(record, dict) or record.get("organization_id") != principal.organization_id:
            raise FileNotFoundError("Approved build not found")
        approval_id = identity(record.get("approval_id"))
        operation_id = identity(record.get("operation_id"))
        with self.operations.records._connection() as connection:
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            connection.execute("SET LOCAL statement_timeout=3000")
            operation = self.operations._select(connection, operation_id)
            row = connection.execute(
                """SELECT a.organization_id,a.approved_by,a.application_id,a.source_ref,
                a.plan,a.plan_digest,a.source_digest,a.account_id,a.region,
                a.revoked_at,a.consumed_key,a.job_id,a.operation_id,
                o.organization_id,p.request_key,p.request_hash
                FROM sky_state.deployment_approvals a
                JOIN sky_state.application_owners o
                  ON o.workspace=a.workspace AND o.application_id=a.application_id
                JOIN sky_state.operations p ON p.workspace=a.workspace AND p.id=a.operation_id
                WHERE a.workspace=%s AND a.id=%s""",
                (self.operations.workspace, approval_id),
            ).fetchone()
        if row is None:
            raise FileNotFoundError("Approved build not found")
        c = operation.command
        expected = (
            principal.organization_id,
            record.get("created_by"),
            record.get("application_id"),
            record.get("source_ref"),
            canonical(record.get("plan")).decode(),
            record.get("plan_digest"),
            record.get("source_digest"),
            self.settings.account_id,
            self.settings.region,
        )
        if (
            row[:9] != expected
            or row[9] is not None
            or not isinstance(row[10], str)
            or not re.fullmatch(r"[a-f0-9]{64}", row[10])
            or row[11] != record.get("id")
            or str(row[12]) != operation_id
            or row[13] != principal.organization_id
            or row[14] != "admission:" + row[10]
            or row[15] != digest([operation.application_id, operation.kind, c])
            or operation.application_id != record.get("application_id")
            or any(
                c.get(k) != record.get(k)
                for k in (
                    "organization_id",
                    "created_by",
                    "source_ref",
                    "source_digest",
                    "plan",
                    "plan_digest",
                    "approval_id",
                    "target",
                )
            )
            or c.get("job_id") != record.get("id")
            or c.get("approved_plan_json") != row[4]
            or digest(json.loads(row[4])) != row[5]
        ):
            raise ValueError("Consumed approval differs from admitted deployment")
        artifact = SourceArtifact.from_record(row[3])
        if (artifact.organization_id, artifact.application_id) != (row[0], row[2]):
            raise ValueError("Approved source belongs to a different application")
        # application_owners.created_by is the app's original creator, which may
        # differ from this deployment's approver. Organization ownership is shared.
        return request_for(operation, self.operations.workspace, self.settings)
