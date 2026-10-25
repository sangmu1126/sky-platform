"""Suspend an existing ECS scaling target and request zero tasks.

No target creation, service deletion, rollback, automatic resume or stop-task.
Manual updates, Express orchestration and external launchers remain outside this
scope. Native writes use single-attempt clients; uncertain outcomes are inspected.
"""

from copy import deepcopy

from adapters.aws.incident_runtime import AwsIncidentRuntimeInspection
from domain.incident_containment import SUSPENDED, target_after_request, validate_containment_target
from domain.incident_runtime import runtime_identity


class AwsIncidentRuntimeContainment(AwsIncidentRuntimeInspection):
    def __init__(self, *, client, autoscaling, sts):
        super().__init__(client=client, sts=sts)
        self.autoscaling = autoscaling

    def _observe(self, result, *, guard):
        account, region, cluster, arn, definition, _, _ = runtime_identity(result)

        def call(client, method, **kwargs):
            guard()
            value = getattr(client, method)(**kwargs)
            guard()
            return value

        if (
            self.client.meta.region_name != region
            or self.autoscaling.meta.region_name != region
            or self.sts.meta.region_name != region
            or call(self.sts, "get_caller_identity").get("Account") != account
        ):
            raise ValueError("Containment account or region differs from registration")
        service = self._service(result, call)
        if service.get("status") != "ACTIVE":
            raise ValueError("Existing active registered service required")
        resource = "service/" + cluster.rsplit("/", 1)[-1] + "/" + arn.rsplit("/", 1)[-1]
        response = call(
            self.autoscaling,
            "describe_scalable_targets",
            ServiceNamespace="ecs",
            ResourceIds=[resource],
            ScalableDimension="ecs:service:DesiredCount",
            MaxResults=50,
        )
        targets = response.get("ScalableTargets", [])
        if response.get("NextToken") or len(targets) != 1:
            raise ValueError("Exactly one existing application scaling target required")
        item = targets[0]
        if (
            item.get("ServiceNamespace") != "ecs"
            or item.get("ResourceId") != resource
            or item.get("ScalableDimension") != "ecs:service:DesiredCount"
        ):
            raise ValueError("Scaling target differs from registered service")
        target = {
            "service_arn": arn,
            "cluster_arn": cluster,
            "task_definition_arn": definition,
            "scaling_resource_id": resource,
            "scalable_target_arn": item.get("ScalableTargetARN"),
            "min_capacity": item.get("MinCapacity"),
            "max_capacity": item.get("MaxCapacity"),
            "suspended_state": item.get("SuspendedState"),
            "desired_count": service["desiredCount"],
        }
        validate_containment_target(target, result)
        return deepcopy(target), call

    def preflight(self, result, *, guard):
        target, _ = self._observe(result, guard=guard)
        return target

    def request(self, result, target, *, guard):
        target = deepcopy(validate_containment_target(target, result))
        for client in (self.client, self.autoscaling):
            if client.meta.config.retries.get("total_max_attempts") != 1:
                raise ValueError("Single-attempt native mutation clients required")
        current, call = self._observe(result, guard=guard)
        if current != target:
            raise ValueError("Scaling configuration changed after containment admission")
        # Set the minimum to zero: RegisterScalableTarget can otherwise restart
        # an already stopped service below its former minimum, even suspended.
        # Omit MaxCapacity so a disappeared target cannot be recreated.
        call(
            self.autoscaling,
            "register_scalable_target",
            ServiceNamespace="ecs",
            ResourceId=target["scaling_resource_id"],
            ScalableDimension="ecs:service:DesiredCount",
            MinCapacity=0,
            SuspendedState=dict(SUSPENDED),
        )
        suspended, _ = self._observe(result, guard=guard)
        if suspended != {**target, "min_capacity": 0, "suspended_state": dict(SUSPENDED)}:
            raise ValueError("Exact scaling suspension not observed; scale-down not issued")
        call(
            self.client,
            "update_service",
            cluster=target["cluster_arn"],
            service=target["service_arn"],
            desiredCount=0,
        )
        observed = self.preflight(result, guard=guard)
        if observed != target_after_request(target):
            raise ValueError("Scale-down outcome not confirmed")
        return observed

    def inspect(self, result, target, *, guard):
        validate_containment_target(target, result)
        observed = self.preflight(result, guard=guard)
        for key in (
            "service_arn",
            "cluster_arn",
            "task_definition_arn",
            "scaling_resource_id",
            "scalable_target_arn",
            "max_capacity",
        ):
            if observed[key] != target[key]:
                raise ValueError("Containment target identity or capacity bounds changed")
        if observed["min_capacity"] not in {0, target["min_capacity"]}:
            raise ValueError("Containment minimum capacity changed unexpectedly")
        return observed
