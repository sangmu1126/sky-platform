"""Operator-configured policies; browser requests cannot choose a DB target."""

import hashlib
import json
import os
import re
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path

from application.operating_review import OperatingReview, ScheduledPromotionPolicy
from domain.access import Action, Principal, ResourceOwner, owner_from_record, permitted
from domain.database import DatabaseBinding
from engine.promotion_policy import CapacityPromotionCriteria, PromotionCostQuote


def load_operating_policies(path, *, account_id, region):
    environment = os.environ.get("SKY_OPERATING_REVIEW_POLICIES_JSON")
    if environment is not None:
        if path:
            raise ValueError("Use policy file or environment, not both")
        raw = environment.encode()
    elif path:
        with Path(path).open("rb") as source:
            raw = source.read(16385)
    else:
        raise ValueError("Explicit operating policies required")
    if len(raw) > 16384:
        raise ValueError("Operating policies exceed the size limit")

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate operating policy field")
            value[key] = item
        return value

    document = json.loads(raw, object_pairs_hook=unique)
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "policies"}
        or type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or not isinstance(document["policies"], list)
        or not 1 <= len(document["policies"]) <= 50
    ):
        raise ValueError("Invalid operating policy document")
    policies = {}
    for item in document["policies"]:
        if (
            not isinstance(item, dict)
            or set(item)
            - {"target_configuration_digest", "capacity_criteria", "isolation_required", "cost_quote"}
            != {
                "job_id",
                "policy_id",
                "review_after",
                "target",
                "max_health_age_seconds",
                "websocket_sessions",
            }
            or not isinstance(item["job_id"], str)
            or not re.fullmatch(r"[a-f0-9]{16}", item["job_id"])
            or item["job_id"] in policies
            or not isinstance(item["target"], dict)
        ):
            raise ValueError("Invalid or duplicate operating job policy")
        target = DatabaseBinding(**item["target"])
        if (target.account_id, target.region) != (account_id, region):
            raise ValueError("Operating target differs from registered account/region")
        criteria = item.get("capacity_criteria")
        quote = item.get("cost_quote")
        if (
            criteria is not None
            and not isinstance(criteria, dict)
            or quote is not None
            and not isinstance(quote, dict)
        ):
            raise ValueError("Operating criteria and cost quote must be objects")
        policies[item["job_id"]] = ScheduledPromotionPolicy(
            item["policy_id"],
            item["review_after"],
            target,
            item["max_health_age_seconds"],
            item["websocket_sessions"],
            item.get("target_configuration_digest"),
            CapacityPromotionCriteria(**criteria) if criteria is not None else None,
            item.get("isolation_required", False),
            PromotionCostQuote(**quote) if quote is not None else None,
        )
    return policies


class OperatingReviewController:
    def __init__(self, records, policies, *, clock=None):
        self.records = records
        self.service = OperatingReview(records)
        self.policies = dict(policies)
        self.clock = clock or (lambda: datetime.now(UTC).isoformat())

    def _policy(self, principal, job_id):
        # Authorization precedes policy lookup to avoid disclosing foreign jobs.
        self.service.writer.snapshot(principal, job_id)
        if job_id not in self.policies:
            raise ValueError("No registered operating policy")
        return self.policies[job_id]

    def review(self, principal, job_id):
        return self.service.review(principal, job_id, self._policy(principal, job_id), now=self.clock())

    def approve(self, principal, job_id, proposal_id):
        return self.service.approve(
            principal, job_id, proposal_id, self._policy(principal, job_id), now=self.clock()
        )

    def review_effect(self, principal, job_id, operation_id, operations):
        from application.promotion_effect import PromotionEffectReview

        return PromotionEffectReview(self.records, operations).review(
            principal, job_id, operation_id, now=self.clock()
        )

    def grant_automation(self, principal, job_id, *, max_incremental_monthly_cents, expires_at):
        return self.service.grant_automation(
            principal,
            job_id,
            self._policy(principal, job_id),
            max_incremental_monthly_cents=max_incremental_monthly_cents,
            expires_at=expires_at,
            now=self.clock(),
        )

    def revoke_automation(self, principal, job_id):
        self._policy(principal, job_id)
        self.service.revoke_automation(principal, job_id)

    def detail(self, principal, job_id):
        if not permitted(principal, Action.READ, ResourceOwner(principal.organization_id, principal.user_id)):
            raise PermissionError("Operating read access denied")
        snapshot = self.records.load_job(job_id)
        if not permitted(principal, Action.READ, owner_from_record(snapshot.record)):
            raise FileNotFoundError("Deployment not found")
        proposal = snapshot.record.get("operating_proposal")
        return {
            "job_id": job_id,
            "proposal": proposal,
            "execution_enabled": False,
            "status_basis": "persisted_review_only",
            "requires_revalidation": True,
            "automation_consent": snapshot.record.get("promotion_automation_consent"),
        }

    def review_automations_once(self, resolve_principal, *, collect=None, coordinate=None, prepare=None):
        """Bounded metadata-only pass; current consent actor is reauthorized.

        CAS and idempotent proposal IDs prevent duplicate approvals from two
        timers. No queue/resource mutation occurs. Collection is explicit and
        must use an audited registered source, never browser-supplied metrics.
        """
        report = []
        for job_id, policy in self.policies.items():
            try:
                record = self.records.load_job(job_id).record
                consent = record.get("promotion_automation_consent")
                if not isinstance(consent, dict):
                    report.append({"job_id": job_id, "status": "no_automation_consent"})
                    continue
                principal = resolve_principal(consent.get("user_id"), consent.get("organization_id"))
                if not isinstance(principal, Principal) or (principal.user_id, principal.organization_id) != (
                    consent.get("user_id"),
                    consent.get("organization_id"),
                ):
                    raise PermissionError("Consent actor membership differs")
                context = (
                    coordinate(principal.organization_id, record.get("application_id"))
                    if coordinate is not None
                    else nullcontext(lambda: None)
                )
                with context as guard:
                    if guard is None:
                        report.append({"job_id": job_id, "status": "review_in_progress"})
                        continue
                    self.service.check_automation(principal, job_id, policy, consent, now=self.clock())
                    if collect is not None:
                        guard()
                        collect(principal, job_id, policy)
                        # A long collection must not reuse a stale membership decision.
                        refreshed = resolve_principal(consent.get("user_id"), consent.get("organization_id"))
                        if not isinstance(refreshed, Principal) or (
                            refreshed.user_id,
                            refreshed.organization_id,
                        ) != (principal.user_id, principal.organization_id):
                            raise PermissionError("Consent actor membership changed during collection")
                        principal = refreshed
                    guard()
                    proposal = self.service.review(
                        principal, job_id, policy, now=self.clock(), automation_consent=consent
                    )
                    outcome = {
                        "job_id": job_id,
                        "status": proposal["status"] if proposal else "criteria_not_met",
                        "proposal_id": proposal["proposal_id"] if proposal else None,
                    }
                    if prepare is not None and proposal and proposal["status"] == "approved":
                        # A timer cannot turn an unrelated/manual approval into
                        # provisioning. Revalidate the same bounded user consent
                        # after all telemetry and metadata work.
                        guard()
                        self.service.check_automation(principal, job_id, policy, consent, now=self.clock())
                        if (
                            proposal.get("decision", {}).get("automatic_approval", {}).get("eligible")
                            is not True
                        ):
                            raise PermissionError("Automatic preparation requires eligible current consent")
                        refreshed = resolve_principal(principal.user_id, principal.organization_id)
                        if not isinstance(refreshed, Principal) or refreshed != principal:
                            raise PermissionError("Consent actor changed before preparation admission")
                        guard()
                        operation = prepare.admit(
                            principal,
                            job_id,
                            proposal["proposal_id"],
                            "auto-prepare-"
                            + hashlib.sha256((job_id + ":" + proposal["proposal_id"]).encode()).hexdigest(),
                        )
                        outcome.update(
                            status="preparation_" + operation.status,
                            operation_id=operation.id,
                            deployment_completed=False,
                        )
                report.append(outcome)
            except (ValueError, TypeError, PermissionError, FileNotFoundError, OSError):
                report.append({"job_id": job_id, "status": "review_blocked"})
        return report
