"""Source recovery runtimes reusing fixed, owned AWS execution adapters."""

import time
from copy import deepcopy


class StatelessSourceRecovery:
    def __init__(self, deployer, *, wait=time.sleep, timeout=900):
        self.deployer, self.wait, self.timeout = deployer, wait, timeout

    def preflight(self, job, recovery_id, build, *, public_access, guard):
        if public_access is not True:
            raise ValueError("Managed HTTPS recovery needs explicit internet exposure consent")
        guard()
        intent = self.deployer.prepare(build["request"], build["result"])
        owner = build["request"]["build_id"].replace("-", "")[:16]
        existing = [t for t in intent["payload"]["tags"] if t["key"] == "sky-attempt"]
        if existing and existing != [{"key": "sky-attempt", "value": owner}]:
            raise ValueError("Recovery deployment ownership differs from the reviewed build")
        if not existing:
            intent["payload"]["tags"].append({"key": "sky-attempt", "value": owner})
        guard()
        return {
            "version": 1,
            "recovery_id": recovery_id,
            "image": build["result"]["image"],
            "public_access": True,
            "owner_attempt": owner,
            "intent": intent,
        }

    def execute(self, plan, *, guard):
        guard()
        self.deployer.create(plan["intent"])
        end = time.monotonic() + self.timeout
        while time.monotonic() < end:
            guard()
            try:
                result = self.deployer.observe(plan["intent"])
            except OSError:
                result = None
            guard()
            if result is not None:
                return self._running_image(plan, result, guard)
            self.wait(5)
        raise TimeoutError("Recovery runtime readiness requires inspection")

    def _running_image(self, plan, result, guard):
        ecs = self.deployer.ecs
        intent = plan["intent"]
        guard()
        listed = ecs.list_tasks(
            cluster="default",
            serviceName=intent["payload"]["serviceName"],
            desiredStatus="RUNNING",
            maxResults=100,
        )
        if listed.get("nextToken") or len(listed.get("taskArns", [])) != 1:
            raise ValueError("Exact one-task recovery inventory required")
        guard()
        observed = ecs.describe_tasks(cluster="default", tasks=listed["taskArns"])
        if observed.get("failures") or len(observed.get("tasks", [])) != 1:
            raise ValueError("Recovery task unavailable")
        task = observed["tasks"][0]
        containers = task.get("containers", [])
        if (
            task.get("taskArn") != listed["taskArns"][0]
            or task.get("taskDefinitionArn") != result["task_definition_arn"]
            or task.get("lastStatus") != "RUNNING"
            or task.get("desiredStatus") != "RUNNING"
            or len(containers) != 1
            or containers[0].get("name") != "Main"
            or containers[0].get("imageDigest") != plan["image"].split("@")[1]
        ):
            raise ValueError("Running recovery image differs from the approved build")
        guard()
        return {
            **result,
            "owner_attempt": plan["owner_attempt"],
            "image_identity": {
                "protocol": "ecs-image-identity-v1",
                "status": "passed",
                "service_arn": intent["service_arn"],
                "task_definition_arn": result["task_definition_arn"],
                "task_arns": listed["taskArns"],
            },
        }

    def observe_verified(self, plan, previous, *, guard):
        guard()
        result = self.deployer.observe(plan["intent"])
        if result is None:
            raise ValueError("Previously verified recovery is not currently ready")
        return self._running_image(plan, result, guard)

    def restrict(self, plan):
        # Restrict only the exact approved service when ownership still matches.
        intent = plan["intent"]
        service = self.deployer.ecs.describe_express_gateway_service(
            serviceArn=intent["service_arn"], include=["TAGS"]
        )["service"]
        expected = {t["key"]: t["value"] for t in intent["payload"]["tags"]}
        actual = {t["key"]: t["value"] for t in service.get("tags", [])}
        if service.get("serviceArn") != intent["service_arn"] or any(
            actual.get(k) != v for k, v in expected.items()
        ):
            raise ValueError("Cannot restrict an unowned recovery service")
        self.deployer.ecs.delete_express_gateway_service(serviceArn=intent["service_arn"])


class PostgreSQLSourceRecovery:
    def __init__(self, runtime):
        self.runtime = runtime

    def preflight(self, job, recovery_id, build, *, public_access, guard):
        # Internal projection only: do not alter the held job or pretend an old
        # artifact review approved the new image. New build evidence is checked
        # independently by the source recovery application before and after use.
        if self.runtime.r.assign_public_ip and public_access is not True:
            raise ValueError("Public PostgreSQL recovery requires explicit internet exposure consent")
        selected = deepcopy(job)
        selected["security_artifact_review"] = {"binding": {"image": build["result"]["image"]}}
        plan = self.runtime.preflight(selected, recovery_id, guard=guard)
        return {**plan, "public_access": public_access}

    def execute(self, plan, *, guard):
        self.runtime.activate(plan, guard=guard)
        submitted = self.runtime.deploy(plan, guard=guard)
        result = self.runtime.verify(plan, submitted, guard=guard)
        result["verification"]["image"] = "verified"
        result["source_recovery_submission"] = deepcopy(submitted)
        return result

    def observe_verified(self, plan, previous, *, guard):
        submitted = previous.get("source_recovery_submission")
        if (
            not isinstance(submitted, dict)
            or set(submitted) != {"service_arn", "task_definition_arn", "container"}
            or submitted["service_arn"] != previous.get("image_identity", {}).get("service_arn")
            or submitted["task_definition_arn"] != previous.get("task_definition_arn")
            or submitted.get("container", {}).get("image") != plan["image"]
        ):
            raise ValueError("Exact persisted PostgreSQL runtime submission required")
        result = self.runtime.verify(plan, submitted, guard=guard)
        result["verification"]["image"] = "verified"
        result["source_recovery_submission"] = deepcopy(submitted)
        return result

    def restrict(self, plan):
        return self.runtime.restrict(plan)
