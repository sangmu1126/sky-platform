"""Operator-declared artifact pins, not a signature or source provenance attestation."""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class RecoveryImageRegistration:
    organization_id: str
    application_id: str
    job_id: str
    incident_id: str
    boundary_id: str
    account_id: str
    region: str
    image: str
    config_digest: str
    source_revision: str
    source_digest: str
    build_reference: str

    def __post_init__(self):
        for name in ("organization_id", "application_id", "incident_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value):
                raise ValueError("Exact operator recovery scope required")
        for name, pattern in {
            "job_id": r"[a-f0-9]{16}",
            "boundary_id": r"[a-f0-9]{32}",
            "account_id": r"[0-9]{12}",
            "region": r"[a-z]{2}-[a-z]+-[0-9]+",
            "source_revision": r"[a-f0-9]{40}",
            "source_digest": r"sha256:[a-f0-9]{64}",
            "config_digest": r"sha256:[a-f0-9]{64}",
            "build_reference": r"https://github\.com/[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+/actions/runs/[1-9][0-9]*",
        }.items():
            value = getattr(self, name)
            if not isinstance(value, str) or not re.fullmatch(pattern, value):
                raise ValueError("Exact recovery source/build/artifact pins required")
        prefix = f"{self.account_id}.dkr.ecr.{self.region}.amazonaws.com/"
        if (
            not isinstance(self.image, str)
            or not re.fullmatch(
                re.escape(prefix) + r"[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[a-f0-9]{64}", self.image
            )
            or len(self.image) > 512
        ):
            raise ValueError("Digest-pinned private ECR recovery image required")

    @property
    def repository(self):
        return self.image.split("/", 1)[1].split("@", 1)[0]

    @property
    def manifest_digest(self):
        return self.image.split("@", 1)[1]
