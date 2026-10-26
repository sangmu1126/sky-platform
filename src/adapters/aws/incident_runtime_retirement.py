"""Retire only a quiescent registered service and its exact task definition.

The application records intent first. Tombstones close that registered ECS
scheduler path; this does not constrain unrelated launchers or AWS administrators.
No automatic recreation/rollback to a compromised service is supported.
"""

from copy import deepcopy

from adapters.aws.incident_runtime import AwsIncidentRuntimeInspection
from domain.incident_runtime import runtime_identity


class AwsIncidentRuntimeRetirement(AwsIncidentRuntimeInspection):
    def __init__(self, *, client, sts, backend="ecs_express"):
        super().__init__(client=client, sts=sts)
        if backend not in {"ecs_express", "ecs_standard"}:
            raise ValueError("Registered ECS retirement backend required")
        self.backend = backend

    def _gateway(self, result, *, guard, inactive=False):
        _, _, _, service, definition, *_ = runtime_identity(result)
        guard()
        gateway = self.client.describe_express_gateway_service(serviceArn=service, include=["TAGS"])[
            "service"
        ]
        guard()
        tags = gateway.get("tags", [])
        if (
            gateway.get("serviceArn") != service
            or gateway.get("status", {}).get("statusCode") != ("INACTIVE" if inactive else "ACTIVE")
            or {t["key"]: t["value"] for t in tags}.get("sky-managed") != "true"
            or {t["key"]: t["value"] for t in tags}.get("sky-attempt") != result["owner_attempt"]
            or len({t["key"] for t in tags}) != len(tags)
            or gateway.get("currentDeployment")
        ):
            raise ValueError("Exact settled owned Express gateway required")
        configurations = gateway.get("activeConfigurations", [])
        if not inactive and (
            len(configurations) != 1 or configurations[0].get("taskDefinitionArn") != definition
        ):
            raise ValueError("Express gateway differs from registered task definition")
        return gateway

    def preflight(self, result, *, guard):
        if self.backend == "ecs_express":
            self._gateway(result, guard=guard)
        observation = self.inspect(result, guard=guard)
        if observation["registered_service_quiescent"] is not True:
            raise ValueError("Quiescent registered service required before retirement")
        _, _, _, _, definition, _, _ = runtime_identity(result)
        guard()
        item = self.client.describe_task_definition(taskDefinition=definition, include=["TAGS"])
        guard()
        tags = item.get("tags", [])
        if (
            item.get("taskDefinition", {}).get("taskDefinitionArn") != definition
            or item["taskDefinition"].get("status") != "ACTIVE"
            or not isinstance(tags, list)
            or (
                self.backend == "ecs_standard"
                and (
                    {t["key"]: t["value"] for t in tags}.get("sky-managed") != "true"
                    or {t["key"]: t["value"] for t in tags}.get("sky-attempt") != result["owner_attempt"]
                    or len({t["key"] for t in tags}) != len(tags)
                )
            )
        ):
            raise ValueError("Exact owned active task definition required")
        return {"runtime": deepcopy(result), "task_arns": observation["task_arns"], "backend": self.backend}

    def retire(self, result, expected, *, guard):
        if self.client.meta.config.retries.get("total_max_attempts") != 1:
            raise ValueError("Single-attempt retirement client required")
        if self.preflight(result, guard=guard) != expected:
            raise ValueError("Runtime retirement target changed since admission")
        _, _, cluster, service, definition, _, _ = runtime_identity(result)
        guard()
        if self.backend == "ecs_express":
            response = self.client.delete_express_gateway_service(serviceArn=service)
        else:
            response = self.client.delete_service(cluster=cluster, service=service, force=False)
        guard()
        if response.get("service", {}).get("serviceArn") != service:
            raise ValueError("Exact service retirement response required")
        # Deleting a service alone is not retirement of its reusable task image.
        response = self.client.deregister_task_definition(taskDefinition=definition)
        guard()
        if (
            response.get("taskDefinition", {}).get("taskDefinitionArn") != definition
            or response["taskDefinition"].get("status") != "INACTIVE"
        ):
            raise ValueError("Task definition retirement outcome uncertain")
        return self.inspect_retired(result, expected, guard=guard)

    def inspect_retired(self, result, expected, *, guard):
        account, region, cluster, service, definition, _, known = runtime_identity(result)
        if (
            not isinstance(expected, dict)
            or set(expected) != {"runtime", "task_arns", "backend"}
            or expected["backend"] != self.backend
            or expected["runtime"] != result
            or not set(known).issubset(expected["task_arns"])
        ):
            raise ValueError("Exact durable retirement intent required")
        if self.client.meta.region_name != region:
            raise ValueError("Retirement region differs from registration")
        guard()
        if self.sts.get_caller_identity().get("Account") != account:
            raise ValueError("Retirement account differs from registration")
        guard()
        if self.backend == "ecs_express":
            self._gateway(result, guard=guard, inactive=True)
        response = self.client.describe_services(cluster=cluster, services=[service], include=["TAGS"])
        guard()
        services = response.get("services", [])
        if response.get("failures") or len(services) != 1:
            raise ValueError("Exact service tombstone required; absence is not evidence")
        observed = services[0]
        if (
            observed.get("serviceArn") != service
            or observed.get("clusterArn") != cluster
            or observed.get("taskDefinition") != definition
            or observed.get("status") != "INACTIVE"
            or any(
                type(observed.get(k)) is not int or observed[k] != 0
                for k in ("desiredCount", "runningCount", "pendingCount")
            )
        ):
            raise ValueError("Registered service has not reached an inactive zero-task state")
        for desired in ("RUNNING", "STOPPED"):
            guard()
            tasks = self.client.list_tasks(
                cluster=cluster, serviceName=service.rsplit("/", 1)[-1], desiredStatus=desired, maxResults=100
            )
            guard()
            if (
                tasks.get("nextToken")
                or not isinstance(tasks.get("taskArns"), list)
                or set(tasks["taskArns"]) - set(expected["task_arns"])
            ):
                raise ValueError("Unregistered tasks or incomplete retirement inventory")
        tasks = self.client.describe_tasks(cluster=cluster, tasks=expected["task_arns"])
        guard()
        if (
            tasks.get("failures")
            or len(tasks.get("tasks", [])) != len(expected["task_arns"])
            or {t.get("taskArn") for t in tasks["tasks"]} != set(expected["task_arns"])
            or any(
                t.get("clusterArn") != cluster
                or t.get("group") != "service:" + service.rsplit("/", 1)[-1]
                or t.get("lastStatus") != "STOPPED"
                or t.get("desiredStatus") != "STOPPED"
                or not t.get("containers")
                or any(c.get("lastStatus") != "STOPPED" for c in t["containers"])
                for t in tasks["tasks"]
            )
        ):
            raise ValueError("Registered historical tasks have not stopped")
        d = self.client.describe_task_definition(taskDefinition=definition)["taskDefinition"]
        guard()
        if d.get("taskDefinitionArn") != definition or d.get("status") != "INACTIVE":
            raise ValueError("Registered task definition is not inactive")
        return {
            "service_arn": service,
            "task_definition_arn": definition,
            "registered_service_retired": True,
            "registered_task_definition_inactive": True,
            "registered_tasks_stopped": True,
            "scope": "registered_ecs_service_and_task_definition",
            "backend": self.backend,
            "arbitrary_aws_launchers_fenced": False,
            "recovery_authorized": False,
            "read_only": True,
        }
