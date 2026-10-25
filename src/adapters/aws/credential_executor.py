"""Observe the recorded preparation task; never infer settled provider requests."""

from datetime import UTC, datetime

from ports.preparation_executor import validate_preparation_executor


class AwsCredentialExecutorObserver:
    def __init__(self, *, session=None, clock=lambda: datetime.now(UTC)):
        self.session, self.clock = session, clock

    def observe(self, executor, *, account_id, region, requested_at, guard):
        identity = validate_preparation_executor(executor)
        arn = identity["task_arn"]
        prefix = f"arn:aws:ecs:{region}:{account_id}:task/"
        if not arn.startswith(prefix):
            raise ValueError("Original executor differs from preparation account and region")
        cluster = f"arn:aws:ecs:{region}:{account_id}:cluster/" + arn.removeprefix(prefix).split("/")[0]
        session = self.session
        if session is None:
            import boto3

            session = boto3.Session(region_name=region)
        ecs, sts = (session.client(name, region_name=region) for name in ("ecs", "sts"))

        def call(client, method, **kwargs):
            guard()
            value = getattr(client, method)(**kwargs)
            guard()
            return value

        if ecs.meta.region_name != region or sts.meta.region_name != region:
            raise ValueError("Executor observation client region mismatch")
        if call(sts, "get_caller_identity").get("Account") != account_id:
            raise ValueError("Executor observer account mismatch")
        response = call(ecs, "describe_tasks", cluster=cluster, tasks=[arn])
        tasks, failures = response.get("tasks"), response.get("failures", [])
        if not isinstance(tasks, list) or not isinstance(failures, list):
            raise ValueError("Exact task response required")  # noqa: TRY004 -- provider response contract
        state, stopped = "unavailable", None
        if failures:
            if (
                tasks
                or len(failures) != 1
                or failures[0].get("arn") != arn
                or failures[0].get("reason") != "MISSING"
            ):
                raise ValueError("Missing task cannot be inferred from an ambiguous failure")
        elif tasks:
            if len(tasks) != 1 or tasks[0].get("taskArn") != arn or tasks[0].get("clusterArn") != cluster:
                raise ValueError("Original executor task identity mismatch")
            task = tasks[0]
            state = "not_stopped"
            if task.get("lastStatus") == "STOPPED" and task.get("desiredStatus") == "STOPPED":
                containers = task.get("containers")
                if (
                    not isinstance(containers, list)
                    or not containers
                    or any(
                        not isinstance(c, dict) or c.get("lastStatus") != "STOPPED" or c.get("taskArn") != arn
                        for c in containers
                    )
                ):
                    raise ValueError("All original task containers must be stopped")
                stamp = task.get("stoppedAt")
                if not isinstance(stamp, datetime) or stamp.tzinfo is None:
                    raise ValueError("Original task stop timestamp required")
                if not datetime.fromisoformat(requested_at) <= stamp <= self.clock():
                    raise ValueError("Task stop time differs from credential preparation")
                state, stopped = "stopped", stamp.isoformat()
        checked = self.clock()
        if not isinstance(checked, datetime) or checked.tzinfo is None:
            raise ValueError("Timezone-aware executor observation time required")
        guard()
        return {
            "task_arn": arn,
            "executor_state": state,
            "stopped_at": stopped,
            "observed_at": checked.isoformat(),
            "provider_requests_settled": False,
            "execution_exclusion_verified": False,
            "recovery_authorized": False,
            "state_changed": False,
            "read_only": True,
        }
