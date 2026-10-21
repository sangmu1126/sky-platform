"""Opt-in hosted target preparation intake; no cloud calls or automatic execution."""

import hashlib
import json
import os
import re

from adapters.aws.job_queue import SqsOperationQueue
from application.database_promotion_workflow import KIND


def load_preparation_api_configuration(*, policies, source):
    enabled = os.environ.get("SKY_DEDICATED_PREPARATION_ENABLED", "false")
    if enabled not in {"true", "false"}:
        raise ValueError("Explicit dedicated preparation enable flag required")
    if enabled == "false":
        return None
    from interfaces.dedicated_database_worker import load_dedicated_configuration

    settings = load_dedicated_configuration(None, source)
    if not policies or any(
        policy.target_configuration_digest != settings.digest
        or policy.cost_quote is None
        or not (policy.capacity_criteria is not None or policy.isolation_required)
        for policy in policies.values()
    ):
        raise ValueError("Costed operating policies must match the dedicated registration")
    url = os.environ.get("SKY_DEDICATED_DATABASE_QUEUE_URL", "")
    if url in {
        os.environ.get(name, "")
        for name in ("SKY_JOB_QUEUE_URL", "SKY_SHARED_DATABASE_QUEUE_URL", "SKY_DATABASE_CUTOVER_QUEUE_URL")
    }:
        raise ValueError("Dedicated preparation queue must be separate")
    SqsOperationQueue(url, region=source.pool.region, account_id=source.pool.account_id, client=object())
    return settings


class DatabasePreparationController:
    def __init__(self, reviews, admission, pool):
        self.reviews, self.admission, self.pool = reviews, admission, pool

    def detail(self, principal, job_id):
        self.reviews.detail(principal, job_id)
        return {
            "job_id": job_id,
            "admission_enabled": self.admission.enabled is True,
            "requires_revalidation": True,
            "automatic_execution": False,
            "operation_kind": KIND,
            "scope": "dedicated_target_preparation_only",
        }

    def submit(self, principal, job_id, *, proposal_id, request_key):
        policy = self.reviews._policy(principal, job_id)
        if policy.cost_quote is None or not (
            policy.capacity_criteria is not None or policy.isolation_required
        ):
            raise ValueError("Costed capacity or isolation policy required")
        if not isinstance(request_key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", request_key):
            raise ValueError("Bounded idempotency request key required")
        binding = self.reviews.service.writer.snapshot(principal, job_id).record.get(
            "workload_database_binding"
        )
        if (
            not isinstance(binding, dict)
            or binding.get("role") != "shared_workload"
            or (binding.get("account_id"), binding.get("region"), binding.get("instance_id"))
            != (self.pool.account_id, self.pool.region, self.pool.instance_id)
        ):
            raise ValueError("Approved source differs from the registered workload pool")
        scoped = hashlib.sha256(
            json.dumps(
                [principal.organization_id, principal.user_id, job_id, request_key], separators=(",", ":")
            ).encode()
        ).hexdigest()
        operation = self.admission.admit(principal, job_id, proposal_id, "prepare-" + scoped)
        return self._receipt(operation, job_id)

    def status(self, principal, job_id, operation_id):
        self.reviews.detail(principal, job_id)
        record = self.reviews.records.load_job(job_id).record
        operation = self.admission.operations.get(operation_id)
        command = operation.command
        if (
            operation.kind != KIND
            or operation.application_id != record.get("application_id")
            or command.get("job_id") != job_id
            or command.get("requested_by", {}).get("organization_id") != principal.organization_id
        ):
            raise FileNotFoundError("Preparation operation not found")
        return self._receipt(operation, job_id)

    @staticmethod
    def _receipt(operation, job_id):
        return {
            "job_id": job_id,
            "operation_id": operation.id,
            "status": operation.status,
            "requires_attention": operation.status == "needs_attention",
            "status_url": f"/api/jobs/{job_id}/database-preparation/{operation.id}",
            "scope": "dedicated_target_preparation_only",
            "data_routing_changed": False,
        }
