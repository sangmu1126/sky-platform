"""Explicit operator intake persists approved work; it never provisions or sends SQS."""

import json
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, replace
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest

from application.operating_review import OperatingReview, deployment_observation_binding
from domain.access import Role
from engine.promotion_policy import PromotionCostQuote
from interfaces.b_runtime import main
from tests.unit.test_deployment_writes import principal
from tests.unit.test_operating_review import ID, NOW

pytest_plugins = ["tests.unit.test_dedicated_database_worker", "tests.unit.test_operating_review"]


@pytest.fixture
def admission_setup(registered, operating_review_setup, monkeypatch):
    settings, _ = registered
    records, policy, _ = operating_review_setup
    policy = replace(
        policy,
        target_configuration_digest=settings.digest,
        isolation_required=True,
        cost_quote=PromotionCostQuote(2500, "registered-quote", "2026-10-12T00:00:00+00:00"),
    )
    records.job["workload_database_binding"]["instance_id"] = settings.source.pool.instance_id
    records.health[-1]["deployment_binding"] = deployment_observation_binding(records.job)
    service = OperatingReview(records)
    proposal = service.review(principal(), ID, policy, now=NOW)
    approved = service.approve(principal(), ID, proposal["proposal_id"], policy, now=NOW)
    monkeypatch.setenv(
        "SKY_OPERATING_REVIEW_POLICIES_JSON",
        json.dumps(
            {
                "schema_version": 1,
                "policies": [{"job_id": ID, **asdict(policy)}],
            }
        ),
    )
    return records, policy, approved


def arguments(approved):
    return [
        "worker",
        "--mode",
        "dedicated-database-admit",
        "--once",
        "--promotion-job-id",
        ID,
        "--promotion-proposal-id",
        approved["proposal_id"],
        "--promotion-request-key",
        "approved-prepare-1",
        "--promotion-user-id",
        "user1",
        "--promotion-organization-id",
        "org1",
    ]


@contextmanager
def runtime(connection, *, actor=None):
    """Freeze the synthetic approval time; all cloud client construction is forbidden."""
    with ExitStack() as stack:
        for name in ("boto3.client", "interfaces.dedicated_database_worker.AwsDedicatedDatabasePreparer"):
            stack.enter_context(patch(name, side_effect=AssertionError("No cloud execution in intake")))
        stack.enter_context(
            patch("interfaces.dedicated_database_worker.load_hosted_identity", return_value=Mock())
        )
        stack.enter_context(
            patch(
                "interfaces.dedicated_database_worker.current_membership", return_value=actor or principal()
            )
        )
        stack.enter_context(
            patch("interfaces.dedicated_database_worker.RotatingDatabaseConnection", return_value=connection)
        )
        clock = stack.enter_context(patch("interfaces.dedicated_database_worker.datetime"))
        clock.now.return_value = datetime.fromisoformat(NOW)
        yield


def test_config_check_performs_no_database_or_cloud_access(admission_setup, capsys):
    _, _, approved = admission_setup
    with (
        runtime(Mock()),
        patch(
            "interfaces.dedicated_database_worker.check_database_ready",
            side_effect=AssertionError("DB access"),
        ),
        patch(
            "interfaces.dedicated_database_worker.PostgresOperationStore.admit",
            side_effect=AssertionError("Admission"),
        ),
    ):
        main(arguments(approved) + ["--check-config"])
    assert "admission/outbox only; no AWS/DB calls" in capsys.readouterr().out


@pytest.mark.parametrize(
    "change",
    [
        "missing_actor",
        "unbounded",
        "foreign_queue",
        "shared_queue",
        "cutover_queue",
        "legacy_policy",
        "operation_id",
        "invalid_key",
    ],
)
def test_invalid_admission_configuration_never_connects(admission_setup, monkeypatch, change):
    _, policy, approved = admission_setup
    args = arguments(approved)
    if change == "missing_actor":
        del args[args.index("--promotion-user-id") : args.index("--promotion-user-id") + 2]
    elif change == "unbounded":
        args.remove("--once")
    elif change == "foreign_queue":
        monkeypatch.setenv(
            "SKY_DEDICATED_DATABASE_QUEUE_URL",
            "https://sqs.ap-northeast-2.amazonaws.com/222222222222/dedicated.fifo",
        )
    elif change == "shared_queue":
        monkeypatch.setenv(
            "SKY_SHARED_DATABASE_QUEUE_URL",
            "https://sqs.ap-northeast-2.amazonaws.com/111111111111/dedicated.fifo",
        )
    elif change == "cutover_queue":
        monkeypatch.setenv(
            "SKY_DATABASE_CUTOVER_QUEUE_URL",
            "https://sqs.ap-northeast-2.amazonaws.com/111111111111/dedicated.fifo",
        )
    elif change == "legacy_policy":
        policy = replace(policy, isolation_required=False)
        monkeypatch.setenv(
            "SKY_OPERATING_REVIEW_POLICIES_JSON",
            json.dumps({"schema_version": 1, "policies": [{"job_id": ID, **asdict(policy)}]}),
        )
    elif change == "operation_id":
        args += ["--operation-id", str(uuid4())]
    else:
        args[args.index("--promotion-request-key") + 1] = "../unsafe"
    with (
        runtime(Mock()),
        patch(
            "interfaces.dedicated_database_worker.check_database_ready",
            side_effect=AssertionError("DB access"),
        ),
        pytest.raises(SystemExit) as error,
    ):
        main(args + ["--check-config"])
    assert error.value.code == 2


def test_admission_options_cannot_be_used_in_operating_timer(admission_setup):
    _, _, approved = admission_setup
    args = arguments(approved)
    args[args.index("--mode") + 1] = "operating-review"
    with pytest.raises(SystemExit) as error:
        main(args)
    assert error.value.code == 2


@pytest.mark.parametrize(
    "change", [None, "unapproved", "foreign_source", "viewer", "foreign_actor", "changed_proposal"]
)
def test_runtime_admits_only_current_owned_approval(admission_setup, capsys, change):
    records, _, approved = admission_setup
    actor = principal()
    if change == "unapproved":
        records.job["operating_proposal"]["status"] = "pending_approval"
    elif change == "foreign_source":
        records.job["workload_database_binding"]["instance_id"] = "foreign"
    elif change == "viewer":
        actor = principal(role=Role.VIEWER)
    elif change == "foreign_actor":
        actor = replace(principal(), organization_id="other")
    elif change == "changed_proposal":
        records.job["operating_proposal"]["approval"]["proposal_id"] = "revoked"
    operations = Mock()
    operations.admit.return_value = SimpleNamespace(
        id=str(uuid4()), attempt_id=str(uuid4()), status="queued", kind="db_dedicated_prepare"
    )
    with (
        runtime(Mock(), actor=actor),
        patch("interfaces.dedicated_database_worker.check_database_ready"),
        patch("interfaces.dedicated_database_worker.PostgresDeploymentRecordStore", return_value=records),
        patch("interfaces.dedicated_database_worker.PostgresOperationStore", return_value=operations),
    ):
        if change:
            with pytest.raises(SystemExit) as error:
                main(arguments(approved))
            assert error.value.code == 1
            operations.admit.assert_not_called()
            assert "operation_id" not in capsys.readouterr().out
        else:
            main(arguments(approved))
            report = json.loads(capsys.readouterr().out)
            assert report["status"] == "queued" and report["delivery"] == "durable_outbox"
            assert report["data_routing_changed"] is False
            app, kind, key, command = operations.admit.call_args.args
            assert (app, kind, key) == ("game", "db_dedicated_prepare", "approved-prepare-1")
            assert command["proposal"] == approved
