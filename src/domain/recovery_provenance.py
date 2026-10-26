"""Pinned verifier policy; source repository commits are distinct from ZIP snapshots."""

import re
from dataclasses import dataclass

from domain.recovery_image import RecoveryImageRegistration


@dataclass(frozen=True)
class RecoveryProvenancePolicy:
    repository: str
    repository_id: str
    owner_id: str
    signer_workflow: str
    signer_digest: str
    source_ref: str
    trusted_root_digest: str

    def __post_init__(self):
        for field, pattern in {
            "repository": r"[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+",
            "repository_id": r"[1-9][0-9]{0,19}",
            "owner_id": r"[1-9][0-9]{0,19}",
            "signer_workflow": r"[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+/\.github/workflows/[A-Za-z0-9_-]+\.ya?ml",
            "signer_digest": r"[a-f0-9]{40}",
            "source_ref": r"refs/(?:heads|tags)/[A-Za-z0-9][A-Za-z0-9_./-]{0,127}",
            "trusted_root_digest": r"sha256:[a-f0-9]{64}",
        }.items():
            value = getattr(self, field)
            if not isinstance(value, str) or not re.fullmatch(pattern, value):
                raise ValueError("Exact operator provenance trust policy required")
        if self.signer_workflow.split("/", 2)[:2] == self.repository.split("/"):
            raise ValueError("Recovery requires a separately trusted reusable signer workflow")
        if ".." in self.source_ref or self.source_ref.endswith("/") or "//" in self.source_ref:
            raise ValueError("Canonical source ref required")


def expected_provenance(registration: RecoveryImageRegistration, policy: RecoveryProvenancePolicy):
    if not isinstance(policy, RecoveryProvenancePolicy):
        raise TypeError("Operator provenance policy required")
    if not registration.build_reference.startswith(f"https://github.com/{policy.repository}/actions/runs/"):
        raise ValueError("Build run repository differs from trusted source repository")
    return {
        "protocol": "github-attestation-recovery-v1",
        "image_digest": registration.manifest_digest,
        "source_repository": policy.repository,
        "source_repository_id": policy.repository_id,
        "source_owner_id": policy.owner_id,
        "source_revision": registration.source_revision,
        "source_ref": policy.source_ref,
        "signer_workflow": policy.signer_workflow,
        "signer_digest": policy.signer_digest,
        "build_reference": registration.build_reference,
        "trusted_root_digest": policy.trusted_root_digest,
        "signed_source_revision_verified": True,
        "build_reference_verified": True,
        "source_snapshot_digest_verified": False,
        "image_safety_verified": False,
        "recovery_authorized": False,
    }


def validate_provenance_receipt(registration, policy, receipt):
    expected = expected_provenance(registration, policy)
    if (
        not isinstance(receipt, dict)
        or set(receipt) != set(expected)
        or any(type(receipt[k]) is not type(v) or receipt[k] != v for k, v in expected.items())
    ):
        raise ValueError("Exact limited signed-provenance receipt required")
    return receipt
