"""Source-bound requirements supplied to automatic deployment planning."""

from __future__ import annotations

import re

from engine.compatibility import InfrastructureProfile, evidence_id


def deployment_requirements(
    profile: InfrastructureProfile,
    source_revision: str,
    *,
    public_access_allowed: bool,
    public_url_required: bool,
) -> dict:
    """Build a provider-neutral contract without treating absence as proof."""
    if (
        not re.fullmatch(r"[a-f0-9]{64}", source_revision)
        or type(public_access_allowed) is not bool
        or type(public_url_required) is not bool
        or (public_url_required and not public_access_allowed)
    ):
        raise ValueError("Invalid deployment requirements input")

    evidence = []
    evidence_by_kind: dict[str, list[str]] = {}
    for kind, paths in (*profile.requirement_evidence, *profile.source_signals):
        identifiers = evidence_by_kind.setdefault(kind, [])
        for path in paths:
            identifier = evidence_id(kind, path)
            if identifier in identifiers:
                continue
            identifiers.append(identifier)
            evidence.append({"id": identifier, "kind": kind, "file": path})

    detected = list(profile.requirements)
    required_capabilities = [*detected]
    if profile.final_image_platform:
        required_capabilities.append("image-platform:" + profile.final_image_platform)
    if public_url_required:
        required_capabilities.append("public-url")

    signal_names = {kind for kind, _paths in profile.source_signals}
    unknowns = {"component-topology", "statelessness"}
    if "websocket" in signal_names:
        unknowns.add("target-websocket-round-trip")
    if "possible-process-local-state" in signal_names:
        unknowns.add("session-affinity-behavior")
    if "unknown" in profile.database_engines:
        unknowns.add("database-engine")

    return {
        "schema_version": 1,
        "source_revision": source_revision,
        "deployment_shape": "single-http-container",
        "required_capabilities": required_capabilities,
        "detected_requirements": detected,
        "database_engines": list(profile.database_engines),
        "declared_image_platform": profile.final_image_platform,
        "access": {
            "public_access_allowed": public_access_allowed,
            "public_url_required": public_url_required,
        },
        "evidence": evidence,
        "hypotheses": [
            {"kind": kind, "evidence_ids": evidence_by_kind.get(kind, [])}
            for kind in sorted(signal_names)
        ],
        "unknowns": sorted(unknowns),
    }
