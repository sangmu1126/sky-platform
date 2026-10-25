"""Exact, bounded automatic-scaling suspension intent; not an IAM fence."""

import re

from domain.incident_runtime import runtime_identity

SUSPENDED = {
    "DynamicScalingInSuspended": True,
    "DynamicScalingOutSuspended": True,
    "ScheduledScalingSuspended": True,
}


def validate_containment_target(target, result):
    account, region, cluster, service, definition, _, _ = runtime_identity(result)
    resource = "service/" + cluster.rsplit("/", 1)[-1] + "/" + service.rsplit("/", 1)[-1]
    if (
        not isinstance(target, dict)
        or set(target)
        != {
            "service_arn",
            "cluster_arn",
            "task_definition_arn",
            "scaling_resource_id",
            "scalable_target_arn",
            "min_capacity",
            "max_capacity",
            "suspended_state",
            "desired_count",
        }
        or target["service_arn"] != service
        or target["cluster_arn"] != cluster
        or target["task_definition_arn"] != definition
        or target["scaling_resource_id"] != resource
        or not isinstance(target["scalable_target_arn"], str)
        or not re.fullmatch(
            re.escape(f"arn:aws:application-autoscaling:{region}:{account}:scalable-target/")
            + r"[A-Za-z0-9-]{1,128}",
            target["scalable_target_arn"],
        )
        or any(
            type(target[key]) is not int or target[key] < 0
            for key in ("min_capacity", "max_capacity", "desired_count")
        )
        or target["max_capacity"] < target["min_capacity"]
        or not isinstance(target["suspended_state"], dict)
        or set(target["suspended_state"]) != set(SUSPENDED)
        or any(type(value) is not bool for value in target["suspended_state"].values())
    ):
        raise ValueError("Exact existing application scaling target required")
    return target


def target_after_request(target):
    return {**target, "min_capacity": 0, "desired_count": 0, "suspended_state": dict(SUSPENDED)}
