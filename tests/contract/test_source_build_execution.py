"""Single consumption and uncertain dispatch against actual PostgreSQL."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest

from adapters.state.incident_execution import PostgresIncidentExecutionControl
from adapters.state.source_build_approvals import PostgresSourceBuildApprovals
from adapters.state.source_build_execution import PostgresSourceBuildExecutions
from application.incident_source_build import IncidentSourceBuildApproval
from application.incident_source_build_execution import IncidentSourceBuildExecution
from application.source_artifacts import SourceArtifactService
from ports.remote_builds import BuildSettings
from ports.state import RecordConflict
from tests.contract.test_incident_source_review import attach
from tests.contract.test_operation_store import database as database  # noqa: PLC0414
from tests.contract.test_operation_store import store as store  # noqa: PLC0414
from tests.unit.test_deployment_writes import ID
from tests.unit.test_incident_source_review import review as review  # noqa: PLC0414
from tests.unit.test_source_artifacts import MemoryStore, upload


@pytest.fixture
def execution(review, store):
    r = attach(review, store)
    old = store.records.load_job(ID)
    r.options["expected_revision"] = store.records.save_job(
        ID, {**old.record, "result": None}, expected_revision=old.revision
    )
    prior_operation = store.admit("game", "deploy", "before-incident", {})
    store.claim(prior_operation.id, prior_operation.attempt_id, "old-worker")
    fenced = PostgresIncidentExecutionControl(store, revalidate=lambda: r.actor).fence(
        r.actor, ID, **r.options
    )
    r.options["expected_revision"] = fenced["metadata_revision"]
    r.moment[0] = datetime.now(UTC)
    memory = MemoryStore()
    sources = SourceArtifactService(memory)
    r.artifact = sources.capture_upload(
        r.actor,
        "game",
        uuid4().hex,
        upload(
            {
                "server.py": 'from http.server import HTTPServer,SimpleHTTPRequestHandler\nHTTPServer(("0.0.0.0",8080),SimpleHTTPRequestHandler).serve_forever()\n',
                "Dockerfile": 'FROM python:3.12-alpine\nWORKDIR /app\nCOPY . .\nEXPOSE 8080\nCMD ["python","server.py"]\n',
            }
        ),
    ).artifact
    r.sources = sources
    r.service.sources = sources
    receipt = r.service.approve(
        r.actor, ID, candidate=r.artifact, review_id="c" * 32, review_ref="SOURCE", seconds=900, **r.options
    )
    r.options["expected_revision"] = receipt["metadata_revision"]
    ledger = PostgresSourceBuildApprovals(store.records, revalidate=lambda: r.actor)
    executions = PostgresSourceBuildExecutions(ledger)
    executions.initialize()
    settings = BuildSettings(
        "owner/builder", "main", "1" * 40, "2" * 40, "source-bucket", "111111111111", "ap-northeast-2"
    )
    clock = lambda: datetime.now(UTC).isoformat()
    consents = IncidentSourceBuildApproval(
        r.service, ledger, settings, clock=clock, reviewer=lambda _: r.actor
    )
    approval_id = "e" * 32
    consents.approve(
        r.actor,
        ID,
        review_id="c" * 32,
        approval_id=approval_id,
        build_id=str(uuid4()),
        review_ref="BUILD",
        seconds=900,
        **r.options,
    )
    builder, objects, verifier = Mock(), Mock(), Mock()
    service = IncidentSourceBuildExecution(
        consents, executions, sources, builder, objects, verifier, clock=clock
    )
    return SimpleNamespace(
        r=r,
        ledger=ledger,
        executions=executions,
        service=service,
        builder=builder,
        objects=objects,
        verifier=verifier,
        approval_id=approval_id,
    )


def run(c):
    return c.service.execute(c.r.actor, ID, approval_id=c.approval_id, **c.r.options)


def test_single_build_dispatch_preserves_source_hold_and_never_dispatches_again(execution, store):
    c = execution
    before = store.records.load_job(ID)
    report = run(c)
    assert report["phase"] == "waiting" and not report["hold_released"]
    assert store.records.load_job(ID) == before
    c.builder.dispatch.assert_called_once()
    request = c.builder.dispatch.call_args.args[0]
    assert request["source_digest"] == c.r.artifact.source_digest
    assert request["source_ref"]["kind"] == "prepared"
    with pytest.raises(RecordConflict):
        run(c)
    c.builder.dispatch.assert_called_once()


def test_two_executors_cannot_dispatch_twice(execution):
    c = execution

    def start(_):
        try:
            return run(c)
        except RecordConflict:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(start, range(2)))
    assert sum(r is not None for r in results) == 1
    c.builder.dispatch.assert_called_once()


def test_uncertain_dispatch_is_observed_without_resending(execution):
    c = execution
    c.builder.dispatch.side_effect = OSError("Acknowledgement lost")
    with pytest.raises(OSError):
        run(c)
    assert c.executions.load(c.r.actor, c.approval_id).record["phase"] == "dispatching"
    c.builder.observe.return_value = None
    assert (
        c.service.observe(c.r.actor, ID, approval_id=c.approval_id, **c.r.options)["phase"] == "dispatching"
    )
    c.builder.dispatch.assert_called_once()
    with pytest.raises(RecordConflict):
        run(c)


def test_lost_reservation_commit_does_not_dispatch_and_is_inspectable(execution, store):
    c = execution
    original = c.executions.reserve

    def lost(*args):
        original(*args)
        raise OSError("Commit lost")

    with patch.object(c.executions, "reserve", side_effect=lost), pytest.raises(OSError):
        run(c)
    c.builder.dispatch.assert_not_called()
    value = c.service.observe(c.r.actor, ID, approval_id=c.approval_id, **c.r.options)
    assert value["phase"] == "reserved" and not value["dispatch_retry_allowed"]


def test_native_result_and_manifest_receipt_required_before_build_verified(execution):
    c = execution
    run(c)
    record = c.executions.load(c.r.actor, c.approval_id)
    request = record.record["request"]
    from ports.remote_builds import digest

    result = {
        k: request[k]
        for k in [
            "build_id",
            "source_digest",
            "plan_digest",
            "repository",
            "workflow_sha",
            "platform_code_sha",
        ]
    }
    result.update(
        version=1,
        request_digest=digest(request),
        run_id=123,
        platform="linux/amd64",
        image="111111111111.dkr.ecr.ap-northeast-2.amazonaws.com/sky-managed@sha256:" + "f" * 64,
        image_digest="sha256:" + "f" * 64,
    )
    c.builder.observe.return_value = {"run_id": 123, "succeeded": True}
    c.objects.result.return_value = result
    c.verifier.verify.return_value = {"image": result["image"], "manifest_bytes_verified": False}
    with pytest.raises(ValueError):
        c.service.observe(c.r.actor, ID, approval_id=c.approval_id, **c.r.options)
    c.verifier.verify.return_value = {
        "image": result["image"],
        "manifest_bytes_verified": True,
        "config_digest": "sha256:" + "a" * 64,
    }
    report = c.service.observe(c.r.actor, ID, approval_id=c.approval_id, **c.r.options)
    assert report["build_verified"] and report["hold_released"] is False


def test_revoked_consent_blocks_pending_observation(execution):
    c = execution
    run(c)
    c.service.consents.revoke(c.r.actor, ID, approval_id=c.approval_id, review_ref="STOP", **c.r.options)
    with pytest.raises(RecordConflict):
        c.service.observe(c.r.actor, ID, approval_id=c.approval_id, **c.r.options)
    c.builder.observe.assert_not_called()
