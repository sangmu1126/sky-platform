"""Credential-free execution identity bound to a preparation's external intent."""

import re
from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True)
class EcsPreparationExecutor:
    task_arn: str

    def __post_init__(self):
        if not isinstance(self.task_arn, str) or not re.fullmatch(
            r"arn:aws:ecs:[a-z]{2}(?:-[a-z]+)+-\d+:\d{12}:task/[A-Za-z0-9_-]{1,255}/[a-f0-9]{32}",
            self.task_arn,
        ):
            raise ValueError("Canonical ECS task identity required")

    def record(self, owner, attempt_id):
        if not isinstance(owner, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", owner):
            raise ValueError("Bounded worker owner required")
        if not isinstance(attempt_id, str) or str(UUID(attempt_id)) != attempt_id:
            raise ValueError("Canonical execution attempt required")
        return {
            "kind": "ecs_task",
            "task_arn": self.task_arn,
            "worker_owner": owner,
            "attempt_id": attempt_id,
        }


def validate_preparation_executor(record):
    if (
        not isinstance(record, dict)
        or set(record) != {"kind", "task_arn", "worker_owner", "attempt_id"}
        or record["kind"] != "ecs_task"
    ):
        raise ValueError("Scoped preparation executor record required")
    expected = EcsPreparationExecutor(record["task_arn"]).record(record["worker_owner"], record["attempt_id"])
    if record != expected:
        raise ValueError("Invalid preparation executor record")
    return expected
