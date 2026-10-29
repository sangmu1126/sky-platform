"""An actual committed PostgreSQL reservation precedes every remote execution grant."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from adapters.aws.build_execution_grant import S3BuildExecutionGrants
from ports.remote_builds import digest, request_for
from tests.contract.test_effect_budget import policy
from tests.contract.test_operation_store import database as database  # noqa: PLC0414
from tests.contract.test_operation_store import store as store  # noqa: PLC0414
from tests.unit.test_build_execution_grants import MemoryS3
from tests.unit.test_remote_build import build_request as build_request  # noqa: PLC0414
from tests.unit.test_remote_build import settings as settings  # noqa: PLC0414


def test_only_matching_current_reserved_build_is_delegated(store, database, settings, build_request):
    command = {
        k: build_request[k]
        for k in (
            "source_ref",
            "source_digest",
            "account_id",
            "region",
            "created_by",
            "plan_digest",
            "approved_plan_json",
            "job_id",
        )
    }
    command.update(version=1, target="aws", organization_id="team", approval_id=str(uuid4()))
    operation = store.admit("game", "deploy", "delegate-once", command)
    lease = store.claim(operation.id, operation.attempt_id, "worker")
    request = request_for(store.get(operation.id), store.workspace, settings)
    store.effect_budget = policy()
    memory = MemoryS3(lambda: datetime.now(UTC))
    grants = S3BuildExecutionGrants(
        settings,
        client=memory,
        authorization=lambda request, lease: store.build_delegation(lease, request, settings),
    )
    assert grants.renew(request, lease, guard=lambda: None) is None
    assert memory.body is None
    intent = {
        "kind": "github_build",
        "build_id": request["build_id"],
        "request_digest": digest(request),
        "repository": settings.repository,
        "workflow_sha": settings.workflow_sha,
    }
    assert store.begin_external(lease, intent)
    grants.renew(request, lease, guard=lambda: None)
    proof = grants.require(request, require_budget=True)
    assert proof["budget_verified"] and proof["budget_caps"]["build_seconds"] == 60
    changed = {**request, "source_digest": "f" * 64}
    with pytest.raises(ValueError, match="approved command"):
        store.build_delegation(lease, changed, settings)
    with database() as db:
        db.execute(
            "UPDATE sky_state.operations SET lease_until=clock_timestamp()-interval '1 second' WHERE workspace=%s AND id=%s",
            (store.workspace, operation.id),
        )
    before = memory.body
    with pytest.raises(ValueError, match="owner"):
        grants.renew(request, lease, guard=lambda: None)
    assert memory.body == before
