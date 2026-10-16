"""Bounded, implementation-backed facts for automatic target selection.

These describe Sky's current deployment configuration, not every feature the
underlying cloud provider could support. Keep them separate from app evidence.
"""

from __future__ import annotations

from engine.backend_identity import backend_identity
from engine.compatibility import TARGET_CAPABILITIES, deployment_access_mode
from engine.cost_exposure import cost_exposure

_DEPLOYMENT_FACTS = {
    "local-docker": {
        "execution": "one container on the Sky host",
        "minimum_instances": 1,
        "maximum_instances": 1,
        "public_url": False,
    },
    "cloud-run": {
        "execution": "Cloud Run service with a linux/amd64 container",
        "minimum_instances": 0,
        "maximum_instances": 1,
        "request_timeout_seconds": 60,
        "public_url": "configuration-dependent",
    },
    "aws-ecs-express": {
        "execution": "ECS Express service running a Fargate task",
        "minimum_instances": 1,
        "maximum_instances": 1,
        "public_url": True,
    },
}


def automatic_target_context(
    targets: list[str], public_access: bool, *, public_url_required: bool = False
) -> list[dict]:
    """Return only facts for offered, implemented automatic server targets."""
    if (
        type(public_access) is not bool
        or type(public_url_required) is not bool
        or (public_url_required and not public_access)
        or not isinstance(targets, list)
        or not targets
        or any(not isinstance(target, str) for target in targets)
        or len(targets) != len(set(targets))
    ):
        raise ValueError("Invalid automatic target selection context")
    context = []
    for target in targets:
        if target not in _DEPLOYMENT_FACTS:
            raise ValueError("Unsupported automatic server target")
        identity = backend_identity(target)
        capabilities = TARGET_CAPABILITIES[target]
        access_mode = deployment_access_mode(target, public_access)
        if access_mode is None or (public_url_required and access_mode != "public"):
            raise ValueError("Automatic target does not support the permitted access mode")
        context.append(
            {
                "target": target,
                "provider": identity.provider,
                "backend": identity.backend,
                "access_mode": access_mode,
                "automatic_selection": {
                    "eligible": True,
                    "scope": "stateless_http_container",
                    "adapter_support": "implemented",
                    "runtime_verification": "pending",
                },
                "unsupported_requirements": [
                    "database",
                    "durable_volume",
                    "background_worker",
                    "custom_network",
                    "migration",
                    "host_control",
                ],
                "automatic_path_supports_database": False,
                "explicit_postgresql_binding": capabilities["postgresql_binding"],
                "sky_deployment": dict(_DEPLOYMENT_FACTS[target]),
                "cost_drivers": cost_exposure(target)["drivers"],
                "monthly_cost_estimate_usd": None,
            }
        )
    return context
