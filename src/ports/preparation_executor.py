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


@dataclass(frozen=True)
class CreateOnlyPreparationProfile:
    """Operator registration of audited code, not a claim inferred from an image.

    The pinned code must issue only the registered CreateDBInstance mutation
    during preparation. Digests identify code; operators must establish this
    property before registering it. Mutable image tags cannot establish it.
    """

    task_definition_arn: str
    images: tuple[tuple[str, str], ...]

    def __post_init__(self):
        if not isinstance(self.task_definition_arn, str) or not re.fullmatch(
            r"arn:aws:ecs:[a-z]{2}(?:-[a-z]+)+-\d+:\d{12}:task-definition/[A-Za-z0-9_-]{1,255}:[1-9][0-9]*",
            self.task_definition_arn,
        ):
            raise ValueError("Pinned task definition revision required")
        if (
            not isinstance(self.images, tuple)
            or not 1 <= len(self.images) <= 10
            or any(
                not isinstance(item, tuple)
                or len(item) != 2
                or not isinstance(item[0], str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,255}", item[0])
                or not isinstance(item[1], str)
                or not re.fullmatch(r"sha256:[a-f0-9]{64}", item[1])
                for item in self.images
            )
            or len({item[0] for item in self.images}) != len(self.images)
        ):
            raise ValueError("Exact container image digests required")

    def record(self):
        return {
            "profile_id": "dedicated-rds-create-only-v1",
            "task_definition_arn": self.task_definition_arn,
            "images": dict(self.images),
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
