from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from adapters.aws.incident_containment import AwsIncidentRuntimeContainment
from application.incident_runtime_containment import FIELD, IncidentRuntimeContainment
from application.security_hold import SecurityHold, require_no_security_hold, security_hold_projection
from domain.access import Role
from domain.incident_containment import SUSPENDED, target_after_request
from ports.state import RecordConflict
from tests.unit.test_deployment_writes import principal
from tests.unit.test_incident_runtime_inspection import application, fixture
from tests.unit.test_operating_review import ID, NOW

pytest_plugins = ["tests.unit.test_operating_review", "tests.unit.test_security_hold_cli"]


def native():
    result, service, _, ecs, sts = fixture()
    service["desiredCount"] = service["runningCount"] = 1
    ecs.meta.config = SimpleNamespace(retries={"total_max_attempts": 1})
    ecs.attach_mock(Mock(), "update_service")
    sts.meta = SimpleNamespace(region_name="ap-northeast-2")
    scaling = Mock(spec=["describe_scalable_targets", "register_scalable_target", "meta"])
    scaling.meta = SimpleNamespace(region_name="ap-northeast-2", config=ecs.meta.config)
    raw = {
        "ServiceNamespace": "ecs",
        "ResourceId": "service/default/test",
        "ScalableDimension": "ecs:service:DesiredCount",
        "ScalableTargetARN": "arn:aws:application-autoscaling:ap-northeast-2:111111111111:scalable-target/"
        + "a" * 32,
        "MinCapacity": 1,
        "MaxCapacity": 4,
        "SuspendedState": {key: False for key in SUSPENDED},
    }
    scaling.describe_scalable_targets.side_effect = lambda **kw: {"ScalableTargets": [deepcopy(raw)]}

    def suspend(**kwargs):
        assert kwargs["MinCapacity"] == 0 and "MaxCapacity" not in kwargs
        raw.update(MinCapacity=0, SuspendedState=deepcopy(kwargs["SuspendedState"]))
        return {"ScalableTargetARN": raw["ScalableTargetARN"]}

    def update(**kwargs):
        assert set(kwargs) == {"cluster", "service", "desiredCount"} and kwargs["desiredCount"] == 0
        service["desiredCount"] = 0
        return {"service": deepcopy(service)}

    scaling.register_scalable_target.side_effect = suspend
    ecs.update_service.side_effect = update
    adapter = AwsIncidentRuntimeContainment(client=ecs, autoscaling=scaling, sts=sts)
    return adapter, result, service, raw, ecs, scaling


def test_native_suspends_existing_scaling_and_requests_zero_without_claiming_task_exit():
    adapter, result, service, _, ecs, scaling = native()
    target = adapter.preflight(result, guard=lambda: None)
    receipt = adapter.request(result, target, guard=lambda: None)
    assert receipt == target_after_request(target)
    assert service["runningCount"] == 1  # acknowledgement is not shutdown evidence
    assert scaling.register_scalable_target.call_count == ecs.update_service.call_count == 1
    assert "StopTask" not in str(ecs.mock_calls)
    assert scaling.register_scalable_target.call_args.kwargs["SuspendedState"] == SUSPENDED
    assert receipt["max_capacity"] == target["max_capacity"] and receipt["min_capacity"] == 0


def test_zero_desired_below_former_minimum_is_never_raised_by_suspension():
    adapter, result, service, _, _, scaling = native()
    service["desiredCount"] = 0
    target = adapter.preflight(result, guard=lambda: None)
    adapter.request(result, target, guard=lambda: None)
    assert scaling.register_scalable_target.call_args.kwargs["MinCapacity"] == 0
    assert "MaxCapacity" not in scaling.register_scalable_target.call_args.kwargs
    assert service["desiredCount"] == 0


@pytest.mark.parametrize(
    "change",
    [
        "owner",
        "definition",
        "account",
        "region",
        "target",
        "capacity",
        "absent",
        "truncated",
        "namespace",
        "retry",
    ],
)
def test_invalid_registration_or_configuration_never_mutates(change):
    adapter, result, service, raw, ecs, scaling = native()
    if change == "owner":
        service["tags"][1]["value"] = "foreign"
    elif change == "definition":
        service["taskDefinition"] += "2"
    elif change == "account":
        adapter.sts.get_caller_identity.return_value["Account"] = "222222222222"
    elif change == "region":
        scaling.meta.region_name = "us-east-1"
    elif change == "target":
        raw["ScalableTargetARN"] = "foreign"
    elif change == "capacity":
        raw["MinCapacity"] = True
    elif change == "absent":
        scaling.describe_scalable_targets.side_effect = lambda **kw: {"ScalableTargets": []}
    elif change == "truncated":
        scaling.describe_scalable_targets.side_effect = lambda **kw: {
            "ScalableTargets": [raw],
            "NextToken": "next",
        }
    elif change == "namespace":
        raw["ResourceId"] = "service/default/foreign"
    else:
        target = adapter.preflight(result, guard=lambda: None)
        ecs.meta.config = SimpleNamespace(retries={"total_max_attempts": 3})
        with pytest.raises(ValueError):
            adapter.request(result, target, guard=lambda: None)
        ecs.update_service.assert_not_called()
        scaling.register_scalable_target.assert_not_called()
        return
    with pytest.raises(ValueError):
        adapter.preflight(result, guard=lambda: None)
    ecs.update_service.assert_not_called()
    scaling.register_scalable_target.assert_not_called()


def test_changed_native_target_since_admission_has_no_mutation():
    adapter, result, _, raw, ecs, scaling = native()
    target = adapter.preflight(result, guard=lambda: None)
    raw["MaxCapacity"] = 5
    with pytest.raises(ValueError):
        adapter.request(result, target, guard=lambda: None)
    ecs.update_service.assert_not_called()
    scaling.register_scalable_target.assert_not_called()


@pytest.mark.parametrize("stage", ["suspend", "scale-down"])
def test_lost_aws_acknowledgement_is_not_retried_or_compensated(stage):
    adapter, result, _, _, ecs, scaling = native()
    target = adapter.preflight(result, guard=lambda: None)
    method = scaling.register_scalable_target if stage == "suspend" else ecs.update_service
    original = method.side_effect

    def lost(**kwargs):
        original(**kwargs)
        raise TimeoutError("outcome unknown")

    method.side_effect = lost
    with pytest.raises(TimeoutError):
        adapter.request(result, target, guard=lambda: None)
    assert scaling.register_scalable_target.call_count == 1
    assert ecs.update_service.call_count == (0 if stage == "suspend" else 1)


def test_inspection_is_readonly_and_does_not_repair_drift():
    adapter, result, _, raw, ecs, scaling = native()
    target = adapter.preflight(result, guard=lambda: None)
    adapter.request(result, target, guard=lambda: None)
    ecs.update_service.reset_mock()
    scaling.register_scalable_target.reset_mock()
    raw["SuspendedState"]["ScheduledScalingSuspended"] = False
    observed = adapter.inspect(result, target, guard=lambda: None)
    assert observed != target_after_request(target)
    ecs.update_service.assert_not_called()
    scaling.register_scalable_target.assert_not_called()


def app(value):
    records, actor, _, args, _ = application(value)
    native_adapter, result, _, _, ecs, scaling = native()
    records.job["result"] = result
    service = IncidentRuntimeContainment(records, native_adapter, clock=lambda: NOW, revalidate=lambda: actor)
    return records, actor, service, args, ecs, scaling


def test_durable_intent_precedes_native_mutation_and_duplicate_request_never_replays(operating_review_setup):
    records, actor, service, args, ecs, scaling = app(operating_review_setup)
    before = deepcopy(records.job)
    mutation = scaling.register_scalable_target.side_effect

    def suspend(**kwargs):
        assert records.job[FIELD]["phase"] == "applying"
        assert records.job["promotion_automation_consent"] is None
        return mutation(**kwargs)

    scaling.register_scalable_target.side_effect = suspend
    report = service.request(actor, ID, **args)
    assert report["phase"] == "scale_down_requested"
    assert records.job["security_hold"] == before["security_hold"]
    assert records.job["security_credential_preparation"] == before["security_credential_preparation"]
    assert records.job["result"] == before["result"]
    assert service.request(actor, ID, **args) == report
    assert scaling.register_scalable_target.call_count == ecs.update_service.call_count == 1
    assert service.status(actor, ID)["record_valid"] is True
    with pytest.raises(ValueError):
        require_no_security_hold(records.job)


@pytest.mark.parametrize("stage", ["preflight", "admit", "suspend", "scale-down", "completion"])
def test_failures_keep_hold_and_never_automatically_retry_or_resume(operating_review_setup, stage):
    records, actor, service, args, ecs, scaling = app(operating_review_setup)
    if stage == "preflight":
        scaling.describe_scalable_targets.side_effect = OSError("must-not-disclose")
    elif stage == "admit":
        service.writer.patch = Mock(side_effect=OSError("must-not-disclose"))
    elif stage == "completion":
        original = service.writer.patch

        def write(*a, **kw):
            if a[3][FIELD]["phase"] == "scale_down_requested":
                raise OSError("must-not-disclose")
            return original(*a, **kw)

        service.writer.patch = write
    else:
        method = scaling.register_scalable_target if stage == "suspend" else ecs.update_service
        mutation = method.side_effect

        def unknown(**kwargs):
            mutation(**kwargs)
            raise TimeoutError("must-not-disclose")

        method.side_effect = unknown
    with pytest.raises(OSError) as error:
        service.request(actor, ID, **args)
    assert "must-not-disclose" not in str(error.value)
    assert records.job["security_hold"] is not None
    if stage in {"preflight", "admit"}:
        assert FIELD not in records.job
        ecs.update_service.assert_not_called()
        scaling.register_scalable_target.assert_not_called()
    else:
        assert records.job[FIELD]["phase"] == "needs_attention"
        calls = (scaling.register_scalable_target.call_count, ecs.update_service.call_count)
        assert service.request(actor, ID, **args)["phase"] == "needs_attention"
        assert calls == (scaling.register_scalable_target.call_count, ecs.update_service.call_count)


@pytest.mark.parametrize("change", ["revision", "role", "membership", "boundary", "incident"])
def test_stale_or_unauthorized_request_cannot_touch_native_apis(operating_review_setup, change):
    records, actor, service, args, ecs, scaling = app(operating_review_setup)
    if change == "revision":
        args["expected_revision"] -= 1
    elif change == "role":
        actor = principal(role=Role.VIEWER)
    elif change == "membership":
        service.scope.revalidate = lambda: principal(role=Role.VIEWER)
    elif change == "boundary":
        args["expected_boundary"] = "f" * 32
    else:
        args["incident_id"] = "foreign"
    with pytest.raises((ValueError, PermissionError, RecordConflict)):
        service.request(actor, ID, **args)
    assert not ecs.mock_calls and not scaling.mock_calls
    assert FIELD not in records.job


def test_revocation_after_suspension_prevents_next_mutation_and_keeps_uncertain_intent(
    operating_review_setup,
):
    records, actor, service, args, ecs, scaling = app(operating_review_setup)
    mutate = scaling.register_scalable_target.side_effect

    def revoke(**kwargs):
        mutate(**kwargs)
        service.scope.revalidate = lambda: principal(role=Role.VIEWER)

    scaling.register_scalable_target.side_effect = revoke
    with pytest.raises(OSError):
        service.request(actor, ID, **args)
    assert records.job[FIELD]["phase"] == "applying"
    ecs.update_service.assert_not_called()


@pytest.mark.parametrize("phase", ["applying", "needs_attention", "scale_down_requested"])
def test_inspection_does_not_resolve_uncertain_phase_or_authorize_recovery(operating_review_setup, phase):
    records, actor, service, args, ecs, scaling = app(operating_review_setup)
    prepared = service.request(actor, ID, **args)
    stored = records.job[FIELD]
    if phase != "scale_down_requested":
        stored.pop("observed_target")
        stored.pop("acknowledged_at")
        stored["phase"] = phase
        if phase == "needs_attention":
            stored["failure_code"] = "outcome_unconfirmed"
    before, writes = deepcopy(records.job), records.save_calls
    ecs.update_service.reset_mock()
    scaling.register_scalable_target.reset_mock()
    report = service.inspect(
        actor,
        ID,
        **{**args, "expected_revision": records.revision, "expected_operation_id": prepared["operation_id"]},
    )
    assert report["persisted_phase"] == phase and report["scale_down_configuration_observed"] is True
    assert all(
        report[key] is False
        for key in (
            "state_changed",
            "scheduler_fenced",
            "execution_exclusion_verified",
            "recovery_authorized",
        )
    )
    assert records.job == before and records.save_calls == writes
    ecs.update_service.assert_not_called()
    scaling.register_scalable_target.assert_not_called()


@pytest.mark.parametrize("record", [{}, {"phase": "complete"}, "invalid"])
def test_malformed_containment_still_blocks_promotion_false_positive_and_exposes_no_details(
    operating_review_setup, record
):
    records, actor, service, args, _, _ = app(operating_review_setup)
    records.job[FIELD] = record
    assert service.status(actor, ID) == {"phase": "needs_attention", "record_valid": False}
    with pytest.raises(ValueError):
        require_no_security_hold(records.job)
    with pytest.raises(ValueError):
        SecurityHold(records).release_false_positive(actor, ID, review_ref="review", now=NOW, **args)
    records.job["security_hold"] = None
    assert security_hold_projection(records.job)["promotion_blocked"] is True


def command(action="contain-runtime"):
    from tests.unit.test_security_hold_cli import arguments

    args = arguments(action) + [
        "--incident-id",
        "INC-1",
        "--expected-revision",
        "1",
        "--expected-boundary",
        "a" * 32,
    ]
    return args + (
        ["--confirm-runtime-containment"]
        if action == "contain-runtime"
        else ["--expected-operation-id", "b" * 32]
    )


@pytest.mark.parametrize("action", ["contain-runtime", "inspect-runtime-containment"])
def test_cli_configuration_check_never_connects_cloud_or_db(configured_cli, action, capsys):
    from interfaces.b_runtime import main

    with (
        patch("boto3.client", side_effect=AssertionError("AWS")),
        patch("interfaces.security_hold.RotatingDatabaseConnection", side_effect=AssertionError("DB")),
    ):
        main(command(action) + ["--check-config"])
    assert "no AWS/DB calls" in capsys.readouterr().out


@pytest.mark.parametrize(
    "change",
    ["confirmation", "foreign-confirmation", "operation", "missing-operation", "pool", "mixed", "revision"],
)
def test_cli_invalid_confirmation_scope_is_rejected(configured_cli, change):
    from interfaces.b_runtime import main

    args = command()
    if change == "confirmation":
        args.remove("--confirm-runtime-containment")
    elif change == "foreign-confirmation":
        args[1] = "inspect-runtime"
    elif change == "operation":
        args += ["--expected-operation-id", "b" * 32]
    elif change == "missing-operation":
        args = command("inspect-runtime-containment")[:-2]
    elif change == "pool":
        args += ["--pool-config", "not-read"]
    elif change == "mixed":
        args += ["--confirm-database-restriction"]
    else:
        args[args.index("--expected-revision") + 1] = "0"
    with pytest.raises(SystemExit) as error:
        main(args + ["--check-config"])
    assert error.value.code == 2


def test_ordinary_read_projection_hides_containment_registration(operating_review_setup):
    from application.deployment_reads import DeploymentReadService

    records, actor, service, args, _, _ = app(operating_review_setup)
    service.request(actor, ID, **args)
    snapshot = SimpleNamespace(job=deepcopy(records.job), health=[])
    reader = DeploymentReadService(Mock(detail=Mock(return_value=snapshot)))
    detail = reader.detail(actor, ID)
    assert FIELD not in detail
    assert detail["security_status"]["promotion_blocked"] is True
