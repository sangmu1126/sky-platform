"""Compare a signed input-binding claim with independently selected build inputs."""

import re

from ports.remote_builds import digest, identity, validate_request


def validate_build_binding(statement, request, *, image_digest, config_digest, run_id):
    artifact, _ = validate_request(request)
    identity(request["build_id"])
    if type(run_id) is not int or not 0 < run_id < 10**20:
        raise ValueError("Exact expected build run required")
    for value in (image_digest, config_digest):
        if not isinstance(value, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", value):
            raise ValueError("Pinned image/config identities required")
    expected = {
        "protocol": "sky-build-input-binding-v1",
        "build_id": request["build_id"],
        "request_digest": digest(request),
        "source_zip_sha256": artifact.sha256,
        "source_zip_size": artifact.size,
        "source_digest": request["source_digest"],
        "plan_digest": request["plan_digest"],
        "image_digest": image_digest,
        "config_digest": config_digest,
        "repository": request["repository"],
        "workflow_sha": request["workflow_sha"],
        "platform_code_sha": request["platform_code_sha"],
        "run_id": run_id,
        "zip_and_source_digest_checked": True,
        "faithful_compilation_verified": False,
        "image_safety_verified": False,
        "recovery_authorized": False,
    }
    if (
        not isinstance(statement, dict)
        or set(statement) != set(expected) | {"archive_digest"}
        or any(type(statement.get(k)) is not type(v) or statement[k] != v for k, v in expected.items())
        or not isinstance(statement.get("archive_digest"), str)
        or not re.fullmatch(r"[a-f0-9]{64}", statement["archive_digest"])
    ):
        raise ValueError("Signed input binding differs from the selected expected request")
    # This comparison must receive its expected request from trusted composition,
    # never from the bundle. It does not confer current deployment/recovery approval.
    return {
        "build_id": request["build_id"],
        "request_digest": digest(request),
        "expected_input_binding_matched": True,
        "current_approval_verified": False,
        "faithful_compilation_verified": False,
        "image_safety_verified": False,
        "recovery_authorized": False,
    }
