"""Bounded operator registration for an already allocated PostgreSQL build."""

import json
from pathlib import Path

from adapters.aws.postgres_build_profile import SharedPostgresBuildProfile
from adapters.aws.shared_database import AwsSharedDatabaseAllocator
from domain.database import DatabaseBinding
from interfaces.shared_database_worker import load_pool_configuration


def load_postgres_build_configuration(path, pool_path, settings, *, check_only=False):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate PostgreSQL deployment registration field")
            value[key] = item
        return value

    with Path(path).open("rb") as stream:
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ValueError("PostgreSQL registration exceeds limit")
    document = json.loads(raw, object_pairs_hook=unique)
    if (
        not isinstance(document, dict)
        or set(document)
        != {
            "schema_version",
            "job_id",
            "binding",
            "security_group",
            "subnets",
            "execution_role",
            "execution_role_id",
        }
        or type(document["schema_version"]) is not int
        or document["schema_version"] != 1
    ):
        raise ValueError("Exact operator PostgreSQL registration required")
    binding = DatabaseBinding(**document["binding"])
    source, _ = load_pool_configuration(pool_path)
    if (binding.account_id, binding.region) != (settings.account_id, settings.region):
        raise ValueError("PostgreSQL account and region differ from builder")
    if check_only:
        # Constructors are configuration-only; no AWS clients or DB calls.
        class Configuration:
            pass

        allocator = Configuration()
        allocator.settings = source
        iam = None
    else:
        import boto3
        from botocore.config import Config

        session = boto3.Session(region_name=settings.region)
        allocator = AwsSharedDatabaseAllocator(source, session=session)
        iam = session.client(
            "iam", config=Config(connect_timeout=5, read_timeout=20, retries={"total_max_attempts": 1})
        )
    return SharedPostgresBuildProfile(
        allocator,
        binding,
        job_id=document["job_id"],
        security_group=document["security_group"],
        subnets=tuple(document["subnets"]) if isinstance(document["subnets"], list) else None,
        execution_role=document["execution_role"],
        execution_role_id=document["execution_role_id"],
        iam=iam,
        logs=None
        if check_only
        else session.client(
            "logs", config=Config(connect_timeout=5, read_timeout=20, retries={"total_max_attempts": 1})
        ),
    )
