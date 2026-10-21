"""Read a preparation worker's task identity from the fixed ECS metadata host."""

import json
import re
import urllib.request

from adapters.aws.task_protection import NoRedirect
from ports.preparation_executor import EcsPreparationExecutor


def load_preparation_executor_identity(uri, *, account_id, region):
    if uri is None:
        return None  # Local execution has no ECS identity; do not fabricate one.
    if not isinstance(uri, str) or not re.fullmatch(
        r"http://169\.254\.170\.2/v4/[A-Za-z0-9_-]{1,128}", uri
    ):
        raise ValueError("Fixed ECS metadata v4 endpoint required")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(uri + "/task", timeout=5) as response:
            if response.status != 200:
                raise ValueError("Task metadata unavailable")
            body = response.read(16385)
            if len(body) > 16384:
                raise ValueError("Task metadata exceeds bound")
            value = json.loads(body)
        identity = EcsPreparationExecutor(value["TaskARN"])
        if not identity.task_arn.startswith(f"arn:aws:ecs:{region}:{account_id}:task/"):
            raise ValueError("Task metadata differs from registered account and region")
        return identity
    except (OSError, ValueError, TypeError, KeyError):
        raise OSError("Preparation executor identity unavailable") from None
