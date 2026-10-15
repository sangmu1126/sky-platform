"""Shared rejection rules for explicit native ZIP execution and its preview.

Passing these rules is not approval: packaging, configuration, permissions and
runtime checks still belong to the native deployment path.
"""

from engine.compatibility import InfrastructureProfile


def native_profile_blockers(profile: InfrastructureProfile, target: str) -> list[str]:
    if target not in {"aws-lambda", "aws-ec2"}:
        raise ValueError("Unknown native AWS target")
    forbidden = {"host-kernel-control", "host-device-access", "websocket"}
    if target == "aws-lambda":
        forbidden.add("persistent-http-server")
    return sorted(set(profile.requirements) | forbidden.intersection(dict(profile.source_signals)))
