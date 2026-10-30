"""Operator-only composition; the API receives the policy, never these credentials."""

import json
import os

from adapters.aws.build_objects import S3BuildObjects
from adapters.aws.hosted_database_build import HostedDatabaseBuild
from adapters.aws.shared_database import AwsSharedDatabaseAllocator
from adapters.aws.source_artifacts import S3ArtifactSettings, S3SourceArtifactStore
from application.database_build_policy import DatabaseBuildPolicy
from application.source_artifacts import SourceArtifactService
from interfaces.shared_database_worker import load_pool_configuration


def load_hosted_database_build(settings):
    import boto3

    policy = DatabaseBuildPolicy.load(os.environ["SKY_DATABASE_BUILD_POLICY_JSON"])
    pool, configuration_digest = load_pool_configuration(None)
    if configuration_digest != policy.configuration_digest or (settings.account_id, settings.region) != (
        policy.account_id,
        policy.region,
    ):
        raise ValueError("Pool registration changed since operator policy approval")
    raw = os.environ.get("SKY_DATABASE_BUILD_EXECUTION_JSON", "")
    if len(raw) > 4096:
        raise ValueError("Bounded execution registration required")
    execution = json.loads(raw)
    if not isinstance(execution, dict) or set(execution) != {"security_group", "subnets", "boundary_arn"}:
        raise ValueError("Exact workload execution registration required")
    session = boto3.Session(region_name=settings.region)
    artifacts = S3ArtifactSettings(settings.bucket, settings.region, settings.account_id)
    return HostedDatabaseBuild(
        policy,
        AwsSharedDatabaseAllocator(pool, session=session),
        SourceArtifactService(S3SourceArtifactStore(artifacts)),
        S3BuildObjects(artifacts),
        settings,
        session=session,
        **execution,
    )
