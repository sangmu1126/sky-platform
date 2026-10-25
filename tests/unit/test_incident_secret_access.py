import json
from copy import deepcopy
from dataclasses import asdict
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from adapters.aws.incident_secret_access import AwsIncidentSecretAccess, read_policy
from application.incident_secret_access import FIELD, IncidentSecretAccess, access_context
from application.security_hold import SecurityHold, require_no_security_hold, security_hold_projection
from domain.access import Role
from domain.incident_credentials import candidate_resource_policy
from domain.incident_secret_access import IncidentSecretRegistration, deny_runtime_secret_policy
from domain.shared_database import PoolAllocationRequest, SharedDatabasePool
from ports.state import RecordConflict
from tests.unit.test_deployment_writes import principal
from tests.unit.test_incident_runtime_inspection import application
from tests.unit.test_operating_review import ID, NOW

pytest_plugins = ["tests.unit.test_operating_review", "tests.unit.test_security_hold_cli"]
KEY = "arn:aws:kms:ap-northeast-2:111111111111:key/11111111-1111-1111-1111-111111111111"


def fixture(value):
    pool = SharedDatabasePool("testpool", "111111111111", "ap-northeast-2", "pool", "sky_pool_control", 50)
    request = PoolAllocationRequest(pool, "org1", "game")
    value[0].job["workload_database_binding"] = asdict(request.binding())
    records, actor, _, args, _ = application(value)
    old = f"arn:aws:secretsmanager:ap-northeast-2:111111111111:secret:sky-pool/testpool/{request.id}-test01"
    records.job["result"]["database"] = {"secret_arn": old}
    registration = IncidentSecretRegistration(request.binding(), "db-PINNED", old, KEY)
    context = access_context(records.job, registration)
    account = registration.binding.account_id
    role_arns = [f"arn:aws:iam::{account}:role/sky-execution", f"arn:aws:iam::{account}:role/sky-app"]
    roles = {
        arn.rsplit("/", 1)[-1]: {
            "Arn": arn,
            "RoleName": arn.rsplit("/", 1)[-1],
            "RoleId": "AROA" + chr(65 + i) * 17,
        }
        for i, arn in enumerate(role_arns)
    }
    clients = {
        "ecs": Mock(spec=["describe_task_definition", "meta"]),
        "iam": Mock(spec=["get_role", "meta"]),
        "sts": Mock(spec=["get_caller_identity", "meta"]),
        "secretsmanager": Mock(
            spec=["describe_secret", "get_resource_policy", "put_resource_policy", "meta"]
        ),
    }
    for client in clients.values():
        client.meta = SimpleNamespace(
            region_name=registration.binding.region, config=SimpleNamespace(retries={"total_max_attempts": 1})
        )
    clients["sts"].get_caller_identity.return_value = {
        "Account": account,
        "Arn": context["preparer_principal"],
    }
    clients["iam"].get_role.side_effect = lambda RoleName: {"Role": deepcopy(roles[RoleName])}
    definition = {
        "taskDefinitionArn": context["runtime"]["task_definition_arn"],
        "executionRoleArn": role_arns[0],
        "taskRoleArn": role_arns[1],
        "containerDefinitions": [
            {"name": "app", "secrets": [{"name": "PGPASSWORD", "valueFrom": old + ":password::"}]}
        ],
    }
    clients["ecs"].describe_task_definition.side_effect = lambda **kw: {
        "taskDefinition": deepcopy(definition)
    }
    candidate = context["candidate_secret_arn"]

    def metadata(arn, tags):
        return {
            "ARN": arn,
            "Name": arn.split(":secret:", 1)[1][:-7],
            "KmsKeyId": KEY,
            "Tags": [{"Key": k, "Value": v} for k, v in tags.items()],
        }

    metadata_map = {
        old: metadata(old, registration.expected_tags()),
        candidate: metadata(
            candidate,
            {
                "sky-managed": "true",
                "sky-database-role": "incident_credential",
                "sky-operation-id": context["candidate_version_id"],
                "sky-rds-resource-id": registration.resource_id,
                "sky-organization-id": "org1",
                "sky-application-id": "game",
            },
        ),
    }
    metadata_map[candidate]["VersionIdsToStages"] = {context["candidate_version_id"]: ["AWSCURRENT"]}
    policies = {old: None, candidate: candidate_resource_policy(candidate, context["preparer_principal"])}
    clients["secretsmanager"].describe_secret.side_effect = lambda SecretId: deepcopy(metadata_map[SecretId])
    clients["secretsmanager"].get_resource_policy.side_effect = lambda SecretId: (
        {} if policies[SecretId] is None else {"ResourcePolicy": json.dumps(policies[SecretId])}
    )

    def put(SecretId, ResourcePolicy, BlockPublicPolicy):
        assert SecretId == old and BlockPublicPolicy is True
        policies[old] = json.loads(ResourcePolicy)
        return {"ARN": old}

    clients["secretsmanager"].put_resource_policy.side_effect = put
    adapter = AwsIncidentSecretAccess(registration, session=Mock(client=lambda name, **kw: clients[name]))
    service = IncidentSecretAccess(
        records, registration, adapter, clock=lambda: NOW, revalidate=lambda: actor
    )
    return SimpleNamespace(
        records=records,
        actor=actor,
        args=args,
        registration=registration,
        context=context,
        clients=clients,
        roles=roles,
        definition=definition,
        metadata=metadata_map,
        policies=policies,
        adapter=adapter,
        service=service,
    )


def test_native_denies_only_original_secret_and_preserves_candidate_and_shared_roles(operating_review_setup):
    f = fixture(operating_review_setup)
    candidate = deepcopy(f.policies[f.context["candidate_secret_arn"]])
    target = f.adapter.preflight(f.context, guard=lambda: None)
    receipt = f.adapter.fence(f.context, target, guard=lambda: None)
    assert receipt["policy_document_verified"] is True and receipt["iam_propagation_verified"] is False
    assert f.policies[f.context["secret_arn"]] == deny_runtime_secret_policy(target)
    assert f.policies[f.context["candidate_secret_arn"]] == candidate
    assert f.clients["secretsmanager"].put_resource_policy.call_count == 1
    assert all(c[0] == "get_role" for c in f.clients["iam"].method_calls)
    assert all(
        c[0] in {"describe_secret", "get_resource_policy", "put_resource_policy"}
        for c in f.clients["secretsmanager"].method_calls
    )
    statement = f.policies[f.context["secret_arn"]]["Statement"][0]
    assert statement["Resource"] == f.registration.secret_arn
    assert all(
        value.startswith("AROA") and value.endswith(":*")
        for value in statement["Condition"]["StringLike"]["aws:userid"]
    )


@pytest.mark.parametrize(
    "change",
    [
        "role-replaced",
        "reference",
        "candidate-policy",
        "candidate-version",
        "kms",
        "owner",
        "deleted",
        "old-policy",
        "caller",
        "region",
        "task-definition",
        "missing-execution-role",
    ],
)
def test_native_invalid_scope_or_existing_policy_never_mutates(operating_review_setup, change):
    f = fixture(operating_review_setup)
    target = f.adapter.preflight(f.context, guard=lambda: None)
    if change == "role-replaced":
        f.roles["sky-execution"]["RoleId"] = "AROA" + "Z" * 17
    elif change == "reference":
        f.definition["containerDefinitions"][0]["secrets"] = []
    elif change == "candidate-policy":
        f.policies[f.context["candidate_secret_arn"]] = None
    elif change == "candidate-version":
        f.metadata[f.context["candidate_secret_arn"]]["VersionIdsToStages"] = {}
    elif change == "kms":
        f.metadata[f.context["secret_arn"]]["KmsKeyId"] = "foreign"
    elif change == "owner":
        f.metadata[f.context["secret_arn"]]["Tags"][0]["Value"] = "false"
    elif change == "deleted":
        f.metadata[f.context["secret_arn"]]["DeletedDate"] = NOW
    elif change == "old-policy":
        f.policies[f.context["secret_arn"]] = {"Version": "2012-10-17", "Statement": []}
    elif change == "caller":
        f.clients["sts"].get_caller_identity.return_value["Arn"] = "arn:aws:iam::111111111111:user/foreign"
    elif change == "region":
        f.clients["ecs"].meta.region_name = "us-east-1"
    elif change == "task-definition":
        f.definition["taskDefinitionArn"] += "2"
    else:
        f.definition.pop("executionRoleArn")
    with pytest.raises(ValueError):
        f.adapter.fence(f.context, target, guard=lambda: None)
    f.clients["secretsmanager"].put_resource_policy.assert_not_called()


def test_preparer_cannot_be_a_role_that_will_be_blocked(operating_review_setup):
    f = fixture(operating_review_setup)
    role = f.roles["sky-execution"]
    f.context["preparer_principal"] = role["Arn"]
    f.clients["sts"].get_caller_identity.return_value = {
        "Account": "111111111111",
        "Arn": "arn:aws:sts::111111111111:assumed-role/sky-execution/session",
        "UserId": role["RoleId"] + ":session",
    }
    with pytest.raises(ValueError):
        f.adapter.preflight(f.context, guard=lambda: None)
    f.clients["secretsmanager"].put_resource_policy.assert_not_called()


def test_inspection_reports_policy_removal_without_repair(operating_review_setup):
    f = fixture(operating_review_setup)
    target = f.adapter.preflight(f.context, guard=lambda: None)
    f.adapter.fence(f.context, target, guard=lambda: None)
    f.policies[f.context["secret_arn"]] = None
    f.clients["secretsmanager"].put_resource_policy.reset_mock()
    observed = f.adapter.inspect(f.context, target, guard=lambda: None)
    assert observed["policy_state"] == "not_recorded" and observed["candidate_protected"] is True
    assert observed["cached_credentials_erased"] is False and observed["recovery_authorized"] is False
    f.clients["secretsmanager"].put_resource_policy.assert_not_called()


def test_mutation_client_must_not_retry_unknown_results(operating_review_setup):
    f = fixture(operating_review_setup)
    target = f.adapter.preflight(f.context, guard=lambda: None)
    f.clients["secretsmanager"].meta.config.retries = {"total_max_attempts": 3}
    with pytest.raises(ValueError):
        f.adapter.fence(f.context, target, guard=lambda: None)
    f.clients["secretsmanager"].put_resource_policy.assert_not_called()


def test_durable_admission_precedes_deny_and_duplicate_request_never_replays(operating_review_setup):
    f = fixture(operating_review_setup)
    before = deepcopy(f.records.job)
    method = f.clients["secretsmanager"].put_resource_policy
    mutate = method.side_effect

    def put(**kw):
        assert f.records.job[FIELD]["phase"] == "applying"
        assert f.records.job["promotion_automation_consent"] is None
        return mutate(**kw)

    method.side_effect = put
    record = f.service.fence(f.actor, ID, **f.args)
    assert record["phase"] == "policy_recorded"
    assert f.records.job["security_credential_preparation"] == before["security_credential_preparation"]
    assert (
        f.records.job["security_hold"] == before["security_hold"]
        and f.records.job["result"] == before["result"]
    )
    assert f.service.fence(f.actor, ID, **f.args) == record and method.call_count == 1
    assert f.service.status(f.actor, ID)["record_valid"] is True
    with pytest.raises(ValueError):
        require_no_security_hold(f.records.job)


@pytest.mark.parametrize("stage", ["preflight", "admit", "policy", "completion", "revoked"])
def test_uncertain_outcomes_keep_hold_and_never_replay_or_remove_policy(operating_review_setup, stage):
    f = fixture(operating_review_setup)
    method = f.clients["secretsmanager"].put_resource_policy
    mutate = method.side_effect
    if stage == "preflight":
        f.clients["ecs"].describe_task_definition.side_effect = OSError("must-not-disclose")
    elif stage == "admit":
        f.service.writer.patch = Mock(side_effect=OSError("must-not-disclose"))
    elif stage == "completion":
        write = f.service.writer.patch

        def patch_record(*args, **kw):
            if args[3][FIELD]["phase"] == "policy_recorded":
                raise OSError("must-not-disclose")
            return write(*args, **kw)

        f.service.writer.patch = patch_record
    else:

        def put(**kw):
            mutate(**kw)
            if stage == "revoked":
                f.service.scope.revalidate = lambda: principal(role=Role.VIEWER)
            else:
                raise TimeoutError("must-not-disclose")

        method.side_effect = put
    with pytest.raises(OSError) as error:
        f.service.fence(f.actor, ID, **f.args)
    assert "must-not-disclose" not in str(error.value) and f.records.job["security_hold"] is not None
    if stage in {"preflight", "admit"}:
        assert FIELD not in f.records.job
        method.assert_not_called()
    else:
        assert f.records.job[FIELD]["phase"] == ("applying" if stage == "revoked" else "needs_attention")
        f.service.scope.revalidate = lambda: f.actor
        prior = method.call_count
        assert f.service.fence(f.actor, ID, **f.args)["phase"] in {"applying", "needs_attention"}
        assert method.call_count == prior


@pytest.mark.parametrize("phase", ["applying", "needs_attention", "policy_recorded"])
def test_readonly_inspection_never_promotes_phase_or_claims_iam_propagation(operating_review_setup, phase):
    f = fixture(operating_review_setup)
    record = f.service.fence(f.actor, ID, **f.args)
    stored = f.records.job[FIELD]
    if phase != "policy_recorded":
        stored.pop("recorded_at")
        stored["phase"] = phase
        if phase == "needs_attention":
            stored["failure_code"] = "outcome_unconfirmed"
    before, writes = deepcopy(f.records.job), f.records.save_calls
    f.clients["secretsmanager"].put_resource_policy.reset_mock()
    observed = f.service.inspect(
        f.actor,
        ID,
        **{
            **f.args,
            "expected_revision": f.records.revision,
            "expected_operation_id": record["operation_id"],
        },
    )
    assert observed["persisted_phase"] == phase and observed["policy_state"] == "runtime_roles_denied"
    assert all(
        observed[key] is False
        for key in (
            "state_changed",
            "iam_propagation_verified",
            "cached_credentials_erased",
            "execution_exclusion_verified",
            "recovery_authorized",
        )
    )
    assert f.records.job == before and f.records.save_calls == writes
    f.clients["secretsmanager"].put_resource_policy.assert_not_called()


@pytest.mark.parametrize(
    "change",
    ["revision", "boundary", "incident", "role", "membership", "unprepared", "wrong-secret", "binding"],
)
def test_wrong_or_stale_context_never_reaches_native_calls(operating_review_setup, change):
    f = fixture(operating_review_setup)
    actor = f.actor
    if change == "revision":
        f.args["expected_revision"] -= 1
    elif change == "boundary":
        f.args["expected_boundary"] = "f" * 32
    elif change == "incident":
        f.args["incident_id"] = "foreign"
    elif change == "role":
        actor = principal(role=Role.VIEWER)
    elif change == "membership":
        f.service.scope.revalidate = lambda: principal(role=Role.VIEWER)
    elif change == "unprepared":
        f.records.job["security_credential_preparation"]["phase"] = "applying"
    elif change == "wrong-secret":
        f.records.job["result"]["database"]["secret_arn"] = "foreign"
    else:
        f.records.job["workload_database_binding"]["application_id"] = "foreign"
    with pytest.raises((ValueError, PermissionError, RecordConflict)):
        f.service.fence(actor, ID, **f.args)
    assert all(not client.mock_calls for client in f.clients.values())


@pytest.mark.parametrize("record", [{}, "invalid", {"phase": "complete"}])
def test_malformed_fence_still_blocks_release_and_public_details_are_hidden(operating_review_setup, record):
    from application.deployment_reads import DeploymentReadService

    f = fixture(operating_review_setup)
    f.records.job[FIELD] = record
    assert f.service.status(f.actor, ID) == {"phase": "needs_attention", "record_valid": False}
    reader = DeploymentReadService(
        Mock(detail=Mock(return_value=SimpleNamespace(job=deepcopy(f.records.job), health=[])))
    )
    assert FIELD not in reader.detail(f.actor, ID)
    with pytest.raises(ValueError):
        SecurityHold(f.records).release_false_positive(f.actor, ID, review_ref="review", now=NOW, **f.args)
    f.records.job["security_hold"] = None
    assert security_hold_projection(f.records.job)["promotion_blocked"] is True
    with pytest.raises(ValueError):
        require_no_security_hold(f.records.job)


@pytest.mark.parametrize("raw", ['{"Statement":[],"Statement":[]}', "null", "[]", "x" * 32769])
def test_ambiguous_policies_are_not_interpreted_as_absent(raw):
    with pytest.raises(ValueError):
        read_policy(raw)


def configuration(path, registration):
    path.write_text(json.dumps({"version": 1, **asdict(registration)}))
    return path


def command(path, action="fence-secret-access"):
    from tests.unit.test_security_hold_cli import arguments

    return (
        arguments(action)
        + [
            "--incident-secret-config",
            str(path),
            "--incident-id",
            "INC-1",
            "--expected-revision",
            "1",
            "--expected-boundary",
            "a" * 32,
        ]
        + (
            ["--confirm-secret-access-fence"]
            if action == "fence-secret-access"
            else ["--expected-operation-id", "b" * 32]
        )
    )


@pytest.mark.parametrize("action", ["fence-secret-access", "inspect-secret-access"])
def test_cli_configuration_does_not_create_cloud_or_state_connections(
    configured_cli, operating_review_setup, tmp_path, capsys, action
):
    from interfaces.b_runtime import main

    f = fixture(operating_review_setup)
    path = configuration(tmp_path / "registration.json", f.registration)
    with (
        patch("boto3.Session", side_effect=AssertionError("AWS")),
        patch("interfaces.security_hold.RotatingDatabaseConnection", side_effect=AssertionError("DB")),
    ):
        main(command(path, action) + ["--check-config"])
    assert "no AWS/DB calls" in capsys.readouterr().out


@pytest.mark.parametrize(
    "change",
    [
        "missing-confirm",
        "wrong-confirm",
        "operation",
        "missing-operation",
        "role-input",
        "pool",
        "mixed",
        "duplicate",
        "environment-conflict",
    ],
)
def test_cli_rejects_ambiguous_or_mutating_options(
    configured_cli, operating_review_setup, tmp_path, monkeypatch, change
):
    from interfaces.b_runtime import main

    f = fixture(operating_review_setup)
    path = configuration(tmp_path / "registration.json", f.registration)
    args = command(path)
    if change == "missing-confirm":
        args.remove("--confirm-secret-access-fence")
    elif change == "wrong-confirm":
        args[1] = "inspect-runtime"
    elif change == "operation":
        args += ["--expected-operation-id", "b" * 32]
    elif change == "missing-operation":
        args = command(path, "inspect-secret-access")[:-2]
    elif change == "role-input":
        args += ["--role-arn", "foreign"]
    elif change == "pool":
        args += ["--pool-config", "not-read"]
    elif change == "mixed":
        args += ["--confirm-runtime-containment"]
    elif change == "duplicate":
        path.write_text(path.read_text().replace('"version": 1', '"version": 1, "version": 1'))
    else:
        monkeypatch.setenv("SKY_INCIDENT_SECRET_ACCESS_JSON", path.read_text())
    with pytest.raises(SystemExit) as error:
        main(args + ["--check-config"])
    assert error.value.code == 2


def test_dedicated_registration_name_is_derived_from_exact_binding(operating_review_setup):
    import hashlib
    from dataclasses import replace

    f = fixture(operating_review_setup)
    b = replace(
        f.registration.binding,
        role="dedicated_workload",
        instance_id="sky-dedicated-test",
        database_name="game",
        owner_ref="dedicated-game",
    )
    digest = hashlib.sha256(json.dumps(asdict(b), sort_keys=True).encode()).hexdigest()[:24]
    arn = f"arn:aws:secretsmanager:{b.region}:{b.account_id}:secret:sky-dedicated/db-PINNED/sky_dedicated_{digest}-test01"
    r = IncidentSecretRegistration(b, "db-PINNED", arn, KEY)
    assert r.expected_tags()["sky-owner-ref"] == b.owner_ref
    with pytest.raises(ValueError):
        IncidentSecretRegistration(b, "db-OTHER", arn, KEY)


def test_status_registration_check_needs_no_provider_clients(
    configured_cli, operating_review_setup, tmp_path, capsys
):
    from interfaces.b_runtime import main
    from tests.unit.test_security_hold_cli import arguments

    f = fixture(operating_review_setup)
    path = configuration(tmp_path / "registration.json", f.registration)
    with (
        patch("boto3.Session", side_effect=AssertionError("AWS")),
        patch("interfaces.security_hold.RotatingDatabaseConnection", side_effect=AssertionError("DB")),
    ):
        main(arguments("status") + ["--incident-secret-config", str(path), "--check-config"])
    assert "no AWS/DB calls" in capsys.readouterr().out


@pytest.mark.parametrize(
    "change", ["scalar", "single-list", "reordered", "extra-allow", "wildcard", "duplicate"]
)
def test_policy_comparison_accepts_only_equivalent_exact_role_id_conditions(operating_review_setup, change):
    from domain.incident_secret_access import runtime_secret_policy_matches

    f = fixture(operating_review_setup)
    target = f.adapter.preflight(f.context, guard=lambda: None)
    if change in {"scalar", "single-list"}:
        target["roles"] = dict([next(iter(target["roles"].items()))])
    policy = deny_runtime_secret_policy(target)
    leaf = policy["Statement"][0]["Condition"]["StringLike"]
    if change == "single-list":
        leaf["aws:userid"] = [leaf["aws:userid"]]
    elif change == "reordered":
        leaf["aws:userid"].reverse()
    elif change == "extra-allow":
        policy["Statement"].append({"Effect": "Allow", "Action": "*", "Resource": "*", "Principal": "*"})
    elif change == "wildcard":
        leaf["aws:userid"] = "AROA*"
    elif change == "duplicate":
        leaf["aws:userid"].append(leaf["aws:userid"][0])
    assert runtime_secret_policy_matches(policy, target) is (change in {"scalar", "single-list", "reordered"})
