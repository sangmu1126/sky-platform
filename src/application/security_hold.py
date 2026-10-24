"""Trusted operator hold for promotion workflows, not attack detection or quarantine.

No network, credential revocation or workload migration occurs here. Clearing a
hold requires a future audited recovery workflow; ordinary promotion approvals
must never clear it. Legacy records without a hold do not attest to safety.
"""

import re
from copy import deepcopy
from datetime import datetime

from application.deployment_writes import DeploymentMetadataWriter
from domain.access import Principal, Role

REASONS = frozenset({"suspected_compromise", "credential_exposure", "untrusted_artifact"})


def require_no_security_hold(job):
    # Malformed/non-null values also block. Absence preserves legacy behavior,
    # and is deliberately not interpreted as a clean security assessment.
    if job.get("security_hold") is not None:
        raise ValueError("Security hold blocks promotion; operator incident review is required")


class SecurityHold:
    def __init__(self, records):
        self.writer = DeploymentMetadataWriter(records)

    def place(self, principal, job_id, *, incident_id, reason, now):
        if not isinstance(principal, Principal) or principal.role is not Role.ADMIN:
            raise PermissionError("Only an organization administrator may record a security hold")
        if not isinstance(incident_id, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", incident_id
        ):
            raise ValueError("A bounded incident reference is required")
        if not isinstance(reason, str) or reason not in REASONS:
            raise ValueError("A supported security hold reason is required")
        try:
            stamp = datetime.fromisoformat(now)
            if stamp.tzinfo is None or stamp.utcoffset() is None:
                raise ValueError()
        except (TypeError, ValueError):
            raise ValueError("A timezone-aware incident time is required") from None
        snapshot = self.writer.snapshot(principal, job_id)
        previous = snapshot.record.get("security_hold")
        if previous is not None:
            if (
                isinstance(previous, dict)
                and previous.get("incident_id") == incident_id
                and previous.get("reason") == reason
            ):
                return deepcopy(previous)
            raise ValueError("An existing security hold requires operator review")
        hold = {
            "incident_id": incident_id,
            "reason": reason,
            "recorded_at": stamp.isoformat(),
            "recorded_by": principal.user_id,
        }
        self.writer.patch(
            principal,
            job_id,
            snapshot.revision,
            {
                "security_hold": hold,
                "promotion_automation_consent": None,
            },
        )
        return deepcopy(hold)
