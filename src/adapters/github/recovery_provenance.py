"""Use GitHub's verifier without AWS/GitHub credentials or executing an image."""

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from domain.recovery_provenance import expected_provenance

PREDICATE = "https://slsa.dev/provenance/v1"
ISSUER = "https://token.actions.githubusercontent.com"


def bounded_file(path, limit):
    with Path(path).open("rb") as stream:
        value = stream.read(limit + 1)
    if not value or len(value) > limit:
        raise ValueError("Attestation input missing or exceeds size bound")
    return value


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate attestation verification field")
        value[key] = item
    return value


class GitHubRecoveryProvenance:
    def __init__(self, policy, *, bundle, trusted_root, executable=None):
        self.policy = policy
        self.bundle = bounded_file(bundle, 2 * 1024 * 1024)
        self.root = bounded_file(trusted_root, 256 * 1024)
        if "sha256:" + hashlib.sha256(self.root).hexdigest() != policy.trusted_root_digest:
            raise ValueError("Operator-pinned attestation trust root mismatch")
        self.executable = executable or shutil.which("gh")
        if (
            not self.executable
            or not Path(self.executable).is_absolute()
            or not os.access(self.executable, os.X_OK)
        ):
            raise ValueError("Installed trusted GitHub CLI verifier required")

    def verify(self, registration, manifest, *, guard):
        expected = expected_provenance(registration, self.policy)
        if (
            not isinstance(manifest, bytes)
            or not manifest
            or len(manifest) > 4 * 1024 * 1024
            or ("sha256:" + hashlib.sha256(manifest).hexdigest() != registration.manifest_digest)
        ):
            raise ValueError("Exact pinned image manifest bytes required for attestation")
        policy = self.policy
        with tempfile.TemporaryDirectory(prefix="sky-recovery-attestation-") as directory:
            root = Path(directory)
            for name, value in (
                ("manifest", manifest),
                ("bundle.jsonl", self.bundle),
                ("trusted-root.json", self.root),
            ):
                (root / name).write_bytes(value)
            command = [
                self.executable,
                "attestation",
                "verify",
                str(root / "manifest"),
                "--bundle",
                str(root / "bundle.jsonl"),
                "--custom-trusted-root",
                str(root / "trusted-root.json"),
                "--repo",
                policy.repository,
                "--signer-workflow",
                policy.signer_workflow,
                "--signer-digest",
                policy.signer_digest,
                "--source-digest",
                registration.source_revision,
                "--source-ref",
                policy.source_ref,
                "--cert-oidc-issuer",
                ISSUER,
                "--predicate-type",
                PREDICATE,
                "--deny-self-hosted-runners",
                "--format",
                "json",
            ]
            # HOME/config/cache are isolated. No ambient cloud keys, GitHub token,
            # Docker config, proxy or user-project executable paths are inherited.
            environment = {
                "PATH": "/usr/bin:/bin",
                "HOME": directory,
                "GH_CONFIG_DIR": directory,
                "XDG_CACHE_HOME": directory,
                "GH_PROMPT_DISABLED": "1",
                "GH_HOST": "github.com",
            }
            try:
                guard()
                result = subprocess.run(
                    command, cwd=directory, env=environment, capture_output=True, timeout=60, check=False
                )
                guard()
                if result.returncode or len(result.stdout) > 2 * 1024 * 1024:
                    raise ValueError("Attestation verification rejected")
                verified = json.loads(result.stdout, object_pairs_hook=unique)
                if not isinstance(verified, list) or not 1 <= len(verified) <= 30:
                    raise ValueError("Bounded verified attestation results required")
                # Every returned result must satisfy our narrower policy; no
                # fallback to unsigned predicate fields or a different signer.
                for entry in verified:
                    self._validate(registration, entry)
            except (OSError, subprocess.SubprocessError, ValueError, TypeError, KeyError):
                raise OSError("Signed recovery provenance unavailable or rejected") from None
            guard()
        return expected

    def _validate(self, registration, entry):
        result = entry["verificationResult"]
        cert = result["signature"]["certificate"]
        p = self.policy
        expected = {
            "issuer": ISSUER,
            "subjectAlternativeName": f"https://github.com/{p.signer_workflow}@{p.signer_digest}",
            "buildSignerURI": f"https://github.com/{p.signer_workflow}@{p.signer_digest}",
            "buildSignerDigest": p.signer_digest,
            "runnerEnvironment": "github-hosted",
            "sourceRepositoryURI": f"https://github.com/{p.repository}",
            "sourceRepositoryDigest": registration.source_revision,
            "sourceRepositoryRef": p.source_ref,
            "sourceRepositoryIdentifier": p.repository_id,
            "sourceRepositoryOwnerURI": "https://github.com/" + p.repository.split("/")[0],
            "sourceRepositoryOwnerIdentifier": p.owner_id,
        }
        if not isinstance(cert, dict) or any(cert.get(k) != v for k, v in expected.items()):
            raise ValueError("Verified signing certificate differs from pinned identity")
        invocation = cert.get("runInvocationURI")
        if not isinstance(invocation, str) or not re.fullmatch(
            re.escape(registration.build_reference) + r"/attempts/[1-9][0-9]*", invocation
        ):
            raise ValueError("Signed build run identity differs from operator registration")
        statement = result["statement"]
        subjects = statement.get("subject")
        if (
            statement.get("_type") != "https://in-toto.io/Statement/v1"
            or statement.get("predicateType") != PREDICATE
            or (
                not isinstance(subjects, list)
                or not 1 <= len(subjects) <= 32
                or not any(
                    isinstance(subject, dict)
                    and subject.get("digest") == {"sha256": registration.manifest_digest[7:]}
                    for subject in subjects
                )
            )
        ):
            raise ValueError("Verified statement must bind the exact image digest")
        # Predicate contents are workflow-controlled; they do not independently
        # prove the uploaded ZIP digest, code safety or recovery authorization.
