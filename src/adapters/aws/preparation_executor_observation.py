"""Observe a pinned ECS executor's stopped state; never stop tasks or resolve DB state.

STOPPED establishes only task state. Requests already accepted by RDS may still
complete. This observation is deliberately not a PreparationRecoveryAuthority.
"""

import hashlib
import json
import re
from datetime import UTC, datetime

from ports.preparation_executor import CreateOnlyPreparationProfile, validate_preparation_executor


class EcsStoppedPreparationObserver:
    def __init__(self, cluster_arn, *, workspace, session=None, clock=lambda: datetime.now(UTC), profile=None):
        match = re.fullmatch(
            r"arn:aws:ecs:([a-z]{2}(?:-[a-z]+)+-\d+):(\d{12}):cluster/([A-Za-z0-9_-]{1,255})",
            cluster_arn if isinstance(cluster_arn, str) else "",
        )
        if not match or not isinstance(workspace, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", workspace):
            raise ValueError("Registered ECS cluster and workspace required")
        self.region, self.account_id, self.cluster_name = match.groups()
        self.cluster_arn, self.workspace, self.clock = cluster_arn, workspace, clock
        if profile is not None and (not isinstance(profile, CreateOnlyPreparationProfile)
                or not profile.task_definition_arn.startswith(
                    f"arn:aws:ecs:{self.region}:{self.account_id}:task-definition/")):
            raise ValueError("Registered execution profile scope mismatch")
        self.profile = profile
        if session is None:
            import boto3

            session = boto3.Session(region_name=self.region)
        self.ecs = session.client("ecs", region_name=self.region)
        self.sts = session.client("sts", region_name=self.region)

    def observe(self, operation, *, guard):
        guard()
        intent = operation.external_intent
        if (operation.kind != "db_dedicated_prepare" or operation.status != "needs_attention"
                or operation.external_pending is not True
                or not isinstance(intent, dict) or intent.get("operation_id") != operation.id
                or intent.get("kind") != operation.kind):
            raise ValueError("Original blocked preparation intent required")
        executor = validate_preparation_executor(intent.get("executor"))
        prefix = f"arn:aws:ecs:{self.region}:{self.account_id}:task/{self.cluster_name}/"
        if not executor["task_arn"].startswith(prefix):
            raise ValueError("Original executor differs from the registered cluster")
        if self.ecs.meta.region_name != self.region or self.sts.meta.region_name != self.region:
            raise ValueError("Executor observation client region mismatch")
        try:
            identity = self.sts.get_caller_identity()
        except Exception:
            raise OSError("Executor observation identity unavailable") from None
        if not isinstance(identity, dict) or identity.get("Account") != self.account_id:
            raise ValueError("Executor observation caller account mismatch")
        guard()
        try:
            response = self.ecs.describe_tasks(cluster=self.cluster_arn, tasks=[executor["task_arn"]])
        except Exception:
            raise OSError("Original executor state unavailable") from None
        guard()
        if not isinstance(response, dict):
            raise ValueError("Executor response cannot establish stopped state")
        tasks, failures = response.get("tasks"), response.get("failures", [])
        if not isinstance(failures, list) or failures or not isinstance(tasks, list) or len(tasks) != 1:
            raise ValueError("Missing or ambiguous executor state is not stopped evidence")
        task = tasks[0]
        if (not isinstance(task, dict) or task.get("taskArn") != executor["task_arn"]
                or task.get("clusterArn") != self.cluster_arn
                or task.get("lastStatus") != "STOPPED" or task.get("desiredStatus") != "STOPPED"):
            raise ValueError("Original executor has not been verified stopped")
        containers = task.get("containers")
        if (not isinstance(containers, list) or not containers
                or any(not isinstance(item, dict) or item.get("lastStatus") != "STOPPED"
                    or item.get("taskArn") != executor["task_arn"] for item in containers)):
            raise ValueError("All original task containers must be verified stopped")
        if self.profile is not None:
            images = {item.get("name"): item.get("imageDigest") for item in containers}
            overrides = task.get("overrides", {})
            override_containers = overrides.get("containerOverrides", []) if isinstance(overrides, dict) else None
            safe_overrides = (isinstance(overrides, dict) and set(overrides) <= {"containerOverrides"}
                and isinstance(override_containers, list)
                and all(isinstance(item, dict) and set(item) == {"name"}
                    and item["name"] in dict(self.profile.images) for item in override_containers))
            if (task.get("taskDefinitionArn") != self.profile.task_definition_arn
                    or len(images) != len(containers) or images != dict(self.profile.images)
                    or not safe_overrides):
                raise ValueError("Original executor code differs from the audited create-only profile")
            self._verify_definition(guard=guard)
        now, stopped = self.clock(), task.get("stoppedAt")
        if (not isinstance(now, datetime) or now.tzinfo is None
                or not isinstance(stopped, datetime) or stopped.tzinfo is None or stopped > now):
            raise ValueError("Verified executor stop time required")
        result = {
            "workspace": self.workspace, "operation_id": operation.id,
            "attempt_id": operation.attempt_id, "operation_version": operation.row_version,
            "executor": executor, "scope": "ecs_executor_stopped_only",
            "stopped_at": stopped.isoformat(), "observed_at": now.isoformat(),
            "provider_requests_settled": False, "recovery_authorized": False,
        }
        if self.profile is not None:
            result["execution_profile"] = self.profile.record()
        digest = hashlib.sha256(json.dumps(result, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        result["evidence_ref"] = "evidence:ecs-stopped/" + digest
        guard()
        return result

    def _verify_definition(self, *, guard):
        """Confirm the registered revision runs the audited preparation mode.

        Image digests still require operator code review. A matching command is
        not proof of code behavior, IAM isolation, or settled provider requests.
        """
        guard()
        try:
            response = self.ecs.describe_task_definition(taskDefinition=self.profile.task_definition_arn)
        except Exception:
            raise OSError("Registered executor definition unavailable") from None
        guard()
        definition = response.get("taskDefinition") if isinstance(response, dict) else None
        containers = definition.get("containerDefinitions") if isinstance(definition, dict) else None
        if (not isinstance(definition, dict)
                or definition.get("taskDefinitionArn") != self.profile.task_definition_arn
                or not isinstance(containers, list) or len(containers) != len(self.profile.images)
                or any(not isinstance(item, dict) or not isinstance(item.get("name"), str)
                    for item in containers)):
            raise ValueError("Task definition differs from the audited create-only execution mode")
        names = [item["name"] for item in containers]
        if (len(set(names)) != len(names) or set(names) != set(dict(self.profile.images))
                or any(item.get("command") != ["worker", "--mode", "dedicated-database-queue"]
                    or ("entryPoint" in item and item["entryPoint"] != ["sky-service"])
                    for item in containers)):
            raise ValueError("Task definition differs from the audited create-only execution mode")
