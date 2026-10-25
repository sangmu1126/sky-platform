"""Pinned recorded ECS workload identity for read-only incident observation."""

import re


def runtime_identity(result):
    if not isinstance(result, dict) or result.get("target") != "aws-ecs-express":
        raise ValueError("Recorded ECS deployment required")
    account, region = result.get("account"), result.get("region")
    if (
        not isinstance(account, str)
        or not re.fullmatch(r"[0-9]{12}", account)
        or not isinstance(region, str)
        or not re.fullmatch(r"[a-z]{2}-[a-z]+-[0-9]+", region)
        or not isinstance(result.get("owner_attempt"), str)
        or not re.fullmatch(r"[a-f0-9]{16}", result["owner_attempt"])
    ):
        raise ValueError("Exact recorded account, region and owner required")
    identity = result.get("image_identity")
    prefix = f"arn:aws:ecs:{region}:{account}:"
    if not isinstance(identity, dict):
        raise ValueError("Recorded runtime image identity required")  # noqa: TRY004 -- identity contract
    service = identity.get("service_arn")
    match = re.fullmatch(
        re.escape(prefix) + r"service/([A-Za-z0-9_-]{1,255})/([A-Za-z0-9_-]{1,255})", service or ""
    )
    tasks = identity.get("task_arns")
    definition = identity.get("task_definition_arn")
    if (
        not match
        or result.get("service") != match[2]
        or identity.get("protocol") != "ecs-image-identity-v1"
        or identity.get("status") != "passed"
        or definition != result.get("task_definition_arn")
        or not isinstance(definition, str)
        or not re.fullmatch(re.escape(prefix) + r"task-definition/[A-Za-z0-9_-]+:[1-9][0-9]*", definition)
        or not isinstance(tasks, list)
        or not 1 <= len(tasks) <= 100
        or any(not isinstance(task, str) for task in tasks)
        or len(set(tasks)) != len(tasks)
    ):
        raise ValueError("Exact recorded service and bounded historical task inventory required")
    cluster = prefix + "cluster/" + match[1]
    task_prefix = prefix + "task/" + match[1] + "/"
    if any(not re.fullmatch(re.escape(task_prefix) + r"[a-f0-9]{32}", task) for task in tasks):
        raise ValueError("Recorded task is outside the registered cluster")
    return account, region, cluster, service, definition, task_prefix, tuple(tasks)
