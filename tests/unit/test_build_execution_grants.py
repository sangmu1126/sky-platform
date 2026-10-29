"""Short worker delegations cannot be extended by a build or borrowed after ownership changes."""

import io
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest
from botocore.exceptions import ClientError

from adapters.aws.build_execution_grant import S3BuildExecutionGrants, execution_guard
from tests.unit.test_remote_build import build_request as build_request  # noqa: PLC0414
from tests.unit.test_remote_build import settings as settings  # noqa: PLC0414


class MemoryS3:
    def __init__(self, clock):
        self.clock = clock
        self.body = None
        self.etag = None

    def get_object(self, **_):
        if self.body is None:
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        return {
            "Body": io.BytesIO(self.body),
            "ETag": self.etag,
            "ResponseMetadata": {
                "HTTPHeaders": {"date": format_datetime(self.clock().replace(microsecond=0), usegmt=True)}
            },
        }

    def put_object(self, **args):
        if ("IfNoneMatch" in args and self.body is not None) or (
            "IfMatch" in args and args["IfMatch"] != self.etag
        ):
            raise ClientError({"Error": {"Code": "PreconditionFailed"}}, "PutObject")
        self.body = args["Body"]
        self.etag = '"' + uuid4().hex + '"'
        return {"ETag": self.etag}


def setup(settings):
    clock = Mock(return_value=datetime.now(UTC))
    memory = MemoryS3(clock)
    lease = SimpleNamespace(epoch=1, owner="worker-one", attempt_id=str(uuid4()))
    scope = SimpleNamespace(bucket=settings.bucket, region=settings.region, account_id=settings.account_id)
    return S3BuildExecutionGrants(scope, client=memory, clock=clock), lease, clock, memory


def test_expired_or_revoked_execution_cannot_request_new_publication(settings, build_request):
    grants, lease, clock, _ = setup(settings)
    grants.renew(build_request, lease, guard=lambda: None)
    assert grants.require(build_request)["current_execution_delegation"]
    clock.return_value += timedelta(seconds=46)
    with pytest.raises(ValueError, match="expired"):
        grants.require(build_request)
    clock.return_value -= timedelta(seconds=46)
    grants.revoke(build_request, lease)
    with pytest.raises(ValueError, match="revoked"):
        grants.require(build_request)
    with pytest.raises(ValueError, match="revoked"):
        grants.renew(build_request, lease, guard=lambda: None)


def test_stale_worker_cannot_revoke_new_lease_or_runner_borrow_it(settings, build_request):
    grants, lease, _, memory = setup(settings)
    grants.renew(build_request, lease, guard=lambda: None)
    grants.require(build_request)
    newer = SimpleNamespace(epoch=2, owner="worker-two", attempt_id=str(uuid4()))
    grants.renew(build_request, newer, guard=lambda: None)
    grants.revoke(build_request, lease)
    with pytest.raises(ValueError, match="owner changed"):
        grants.require(build_request)
    reader = S3BuildExecutionGrants(grants.settings, client=memory, clock=grants.clock)
    assert reader.require(build_request)["lease_epoch"] == 2
    with pytest.raises(ValueError, match="newer"):
        grants.renew(build_request, lease, guard=lambda: None)


def test_permission_loss_during_write_revokes_own_delegation(settings, build_request):
    grants, lease, _, _ = setup(settings)
    guard = Mock(side_effect=[None, None, ValueError("permission revoked")])
    with pytest.raises(ValueError, match="permission revoked"):
        grants.renew(build_request, lease, guard=guard)
    with pytest.raises(ValueError, match="revoked"):
        grants.require(build_request)


def test_hosted_caller_cannot_disable_grants_or_trigger_credentials_during_factory(settings, build_request):
    scope = SimpleNamespace(bucket=settings.bucket, region=settings.region, account_id=settings.account_id)
    with pytest.raises(ValueError):
        execution_guard(
            build_request,
            scope,
            lambda: None,
            environment={"GITHUB_ACTIONS": "true", "SKY_REQUIRE_EXECUTION_GRANTS": "false"},
        )
    checker = Mock()
    guard = execution_guard(build_request, scope, checker, environment={})
    guard()
    checker.assert_called_once()
