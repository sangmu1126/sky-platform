from copy import deepcopy
from dataclasses import asdict
from unittest.mock import Mock

import pytest

from adapters.aws.postgres_build_profile import SharedPostgresBuildProfile, verify_postgres_task
from domain.database import DatabaseBinding
from ports.remote_builds import canonical, digest
from tests.unit.test_built_deployment import prepared as prepared  # noqa: PLC0414


@pytest.fixture
def postgres(prepared):
    adapter, request, result, *_ = prepared
    binding = DatabaseBinding(
        "team",
        "game",
        "shared_workload",
        adapter.settings.account_id,
        adapter.settings.region,
        "sky-pool-team",
        "sky_app_owned",
        "allocation-owned",
    )
    allocation = {
        "binding": asdict(binding),
        "secret_ref": f"arn:aws:secretsmanager:{binding.region}:{binding.account_id}:secret:sky-pool/team/owned-abcdef",
        "secret_version": "e" * 32,
        "host": "pool.abc.ap-northeast-2.rds.amazonaws.com",
        "port": 5432,
        "kms_key_arn": f"arn:aws:kms:{binding.region}:{binding.account_id}:key/" + "f" * 36,
        "resource_id": "db-IMMUTABLE",
        "login_role": "sky_login_owned",
        "tls_verified": True,
        "cross_database_access_denied": True,
    }
    allocator = Mock()
    allocator.settings.allowed_client_groups = ("sg-12345678",)
    allocator.settings.pool.account_id = binding.account_id
    allocator.settings.pool.region = binding.region
    allocator.settings.pool.instance_id = binding.instance_id
    allocator.inspect_allocation.return_value = allocation
    allocator.clients = {"ec2": Mock()}
    allocator.clients["ec2"].describe_subnets.return_value = {
        "Subnets": [
            {
                "SubnetId": name,
                "AvailabilityZone": zone,
                "VpcId": allocator.settings.vpc_id,
                "OwnerId": binding.account_id,
                "State": "available",
            }
            for name, zone in [("subnet-12345678", "az-a"), ("subnet-abcdef01", "az-b")]
        ]
    }
    iam = Mock()
    role = f"arn:aws:iam::{binding.account_id}:role/sky-workload-fixture"
    profile = SharedPostgresBuildProfile(
        allocator,
        binding,
        job_id=request["job_id"],
        security_group="sg-12345678",
        subnets=("subnet-12345678", "subnet-abcdef01"),
        execution_role=role,
        execution_role_id="AROA" + "A" * 17,
        iam=iam,
        logs=Mock(),
    )
    profile.logs.describe_log_groups.return_value = {
        "logGroups": [{"logGroupName": profile.log_group, "retentionInDays": 7}]
    }
    profile.logs.list_tags_log_group.return_value = {
        "tags": {
            "sky-managed": "true",
            "sky-job": request["job_id"],
            "sky-application": "game",
            "sky-organization": "team",
        }
    }
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": binding.account_id},
                    "ArnLike": {"aws:SourceArn": f"arn:aws:ecs:{binding.region}:{binding.account_id}:*"},
                },
            }
        ],
    }
    iam.get_role.return_value = {
        "Role": {
            "Arn": role,
            "RoleId": profile.role_id,
            "AssumeRolePolicyDocument": trust,
            "Tags": [
                {"Key": k, "Value": v}
                for k, v in {
                    "sky-managed": "true",
                    "sky-job": request["job_id"],
                    "sky-application": "game",
                    "sky-organization": "team",
                }.items()
            ],
        }
    }
    iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
    iam.list_role_policies.return_value = {"PolicyNames": ["SkyWorkloadExecution"]}
    iam.get_role_policy.return_value = {
        "PolicyDocument": profile.execution_policy(result["image"], allocation)
    }
    import json

    plan = json.loads(request["approved_plan_json"])
    plan.update(
        database_profile="shared-postgres-v1",
        required_env=["PGUSER", "PGPASSWORD"],
        infrastructure_profile={"requirements": ["database"], "database_engines": ["postgresql"]},
    )
    request = {**request, "approved_plan_json": canonical(plan).decode(), "plan_digest": digest(plan)}
    result = {**result, "request_digest": digest(request), "plan_digest": digest(plan)}
    adapter.database_profile = profile
    return adapter, profile, request, result, plan, allocator, iam


def test_existing_allocation_binds_versioned_secret_and_leaves_app_role_absent(postgres):
    adapter, profile, request, result, _, allocator, _ = postgres
    intent = adapter.prepare(request, result)
    payload = intent["payload"]
    assert payload["executionRoleArn"] == profile.role
    assert "taskRoleArn" not in payload
    assert payload["networkConfiguration"] == {
        "securityGroups": ["sg-12345678"],
        "subnets": list(profile.subnets),
    }
    assert all(x["valueFrom"].endswith("::" + "e" * 32) for x in payload["primaryContainer"]["secrets"])
    assert "password" not in intent["database_registration"]
    assert all(x["name"] not in {"PGPASSWORD", "PGUSER"} for x in payload["primaryContainer"]["environment"])
    allocator.allocate.assert_not_called()
    allocator.initialize.assert_not_called()


@pytest.mark.parametrize(
    "change", ["organization", "job", "mysql", "worker", "env", "role_id", "role_policy"]
)
def test_incompatible_or_changed_registration_never_creates_service(postgres, change):
    adapter, _, request, result, plan, _, iam = postgres
    if change == "organization":
        request["source_ref"]["organization_id"] = "outsider"
    elif change == "job":
        request["job_id"] = "b" * 16
    elif change == "mysql":
        plan["infrastructure_profile"]["database_engines"] = ["mysql"]
    elif change == "worker":
        plan["infrastructure_profile"]["requirements"].append("background-worker")
    elif change == "env":
        plan["required_env"].append("ADMIN_PASSWORD")
    elif change == "role_id":
        iam.get_role.return_value["Role"]["RoleId"] = "AROA" + "B" * 17
    else:
        iam.get_role_policy.return_value = {"PolicyDocument": {"Statement": [{"Action": "*"}]}}
    request.update(approved_plan_json=canonical(plan).decode(), plan_digest=digest(plan))
    result.update(request_digest=digest(request), plan_digest=digest(plan))
    with pytest.raises(ValueError):
        adapter.prepare(request, result)
    adapter.ecs.create_express_gateway_service.assert_not_called()


def test_secret_rotation_between_intent_and_observation_requires_review(postgres):
    adapter, profile, request, result, _, allocator, _ = postgres
    intent = adapter.prepare(request, result)
    allocator.inspect_allocation.return_value = {
        **deepcopy(intent["database_registration"]),
        "secret_version": "f" * 32,
    }
    with pytest.raises(ValueError, match="changed"):
        profile.verify(intent)


def test_actual_task_digest_mismatch_does_not_pass_definition_only_verification(postgres):
    adapter, _, request, result, *_ = postgres
    intent = adapter.prepare(request, result)
    ecs = adapter.ecs
    ecs.list_tasks.return_value = {"taskArns": ["owned-task"]}
    ecs.describe_tasks.return_value = {
        "tasks": [
            {
                "taskArn": "owned-task",
                "taskDefinitionArn": "owned-definition",
                "group": "service:" + intent["payload"]["serviceName"],
                "lastStatus": "RUNNING",
                "desiredStatus": "RUNNING",
                "containers": [{"name": "Main", "imageDigest": "sha256:" + "0" * 64}],
            }
        ]
    }
    with pytest.raises(ValueError, match="Actual PostgreSQL task image"):
        verify_postgres_task(ecs, intent, "owned-definition")
