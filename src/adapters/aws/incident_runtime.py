"""Bounded read-only ECS workload observation, not executor exclusion.

Missing historical tasks, truncated inventories and account/ownership mismatch
fail closed. No stop/update/delete calls, credential reads, or IAM changes.
Even a quiescent service can restart later: this is not a scheduling fence.
"""

import re
from copy import deepcopy

from domain.incident_runtime import runtime_identity


class AwsIncidentRuntimeInspection:
    def __init__(self, *, client, sts):
        self.client, self.sts = client, sts

    def inspect(self, result, *, guard):
        result = deepcopy(result)
        account, region, cluster, arn, definition, task_prefix, known = runtime_identity(result)

        def call(client, method, **kwargs):
            guard()
            value = getattr(client, method)(**kwargs)
            guard()
            return value

        if call(self.sts, "get_caller_identity").get("Account") != account:
            raise ValueError("Runtime inspection account differs from deployment")
        if self.client.meta.region_name != region:
            raise ValueError("Runtime inspection client region differs from deployment")

        def service():
            response = call(
                self.client, "describe_services", cluster=cluster, services=[arn], include=["TAGS"]
            )
            services = response.get("services", [])
            if response.get("failures") or len(services) != 1:
                raise ValueError("Registered service could not be observed")
            item = services[0]
            tags = item.get("tags", [])
            if (
                item.get("serviceArn") != arn
                or item.get("clusterArn") != cluster
                or item.get("status") not in {"ACTIVE", "DRAINING", "INACTIVE"}
                or item.get("taskDefinition") != definition
                or not isinstance(tags, list)
                or any(not isinstance(tag, dict) or set(tag) != {"key", "value"} for tag in tags)
                or len({tag["key"] for tag in tags}) != len(tags)
                or {tag["key"]: tag["value"] for tag in tags}.get("sky-managed") != "true"
                or {tag["key"]: tag["value"] for tag in tags}.get("sky-attempt") != result["owner_attempt"]
                or any(
                    type(item.get(key)) is not int or item[key] < 0
                    for key in ("desiredCount", "runningCount", "pendingCount")
                )
                or not isinstance(item.get("deployments"), list)
            ):
                raise ValueError("Service ownership, identity or counts could not be verified")
            return item

        before = service()
        inventory = set(known)
        # RUNNING includes pending starts; STOPPED includes tasks requested to
        # stop that may still be draining. Neither list alone is sufficient.
        for desired in ("RUNNING", "STOPPED"):
            response = call(
                self.client,
                "list_tasks",
                cluster=cluster,
                serviceName=arn.rsplit("/", 1)[-1],
                desiredStatus=desired,
                maxResults=100,
            )
            tasks = response.get("taskArns")
            if (
                response.get("nextToken")
                or not isinstance(tasks, list)
                or len(tasks) > 100
                or any(
                    not isinstance(task, str)
                    or not re.fullmatch(re.escape(task_prefix) + r"[a-f0-9]{32}", task)
                    for task in tasks
                )
                or len(set(tasks)) != len(tasks)
            ):
                raise ValueError("Complete bounded service inventory required")
            inventory.update(tasks)
        if len(inventory) > 100:
            raise ValueError("Service inventory exceeds bounded inspection")
        response = call(self.client, "describe_tasks", cluster=cluster, tasks=sorted(inventory))
        tasks = response.get("tasks", [])
        if (
            response.get("failures")
            or len(tasks) != len(inventory)
            or {task.get("taskArn") for task in tasks} != inventory
            or any(
                task.get("taskDefinitionArn") != definition for task in tasks if task.get("taskArn") in known
            )
            or any(
                task.get("clusterArn") != cluster or task.get("group") != "service:" + arn.rsplit("/", 1)[-1]
                for task in tasks
            )
        ):
            raise ValueError("Historical and current task observations must be complete")
        after = service()
        if after != before:
            raise ValueError("Service changed during inspection")
        stopped = all(
            task.get("lastStatus") == "STOPPED"
            and task.get("desiredStatus") == "STOPPED"
            and isinstance(task.get("containers"), list)
            and task["containers"]
            and all(container.get("lastStatus") == "STOPPED" for container in task["containers"])
            for task in tasks
        )
        quiescent = stopped and all(
            before[key] == 0 for key in ("desiredCount", "runningCount", "pendingCount")
        )
        # Deployments must also be fully scaled down, including older revisions.
        for deployment in before["deployments"]:
            for key in ("desiredCount", "runningCount", "pendingCount"):
                if type(deployment.get(key)) is not int or deployment[key] < 0:
                    raise ValueError("Complete deployment counts required")
                quiescent = quiescent and deployment[key] == 0
        return {
            "service_arn": arn,
            "cluster_arn": cluster,
            "task_arns": sorted(inventory),
            "registered_service_quiescent": bool(quiescent),
            "read_only": True,
            "execution_exclusion_verified": False,
            "scheduler_fenced": False,
            "state_changed": False,
        }
