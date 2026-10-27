"""Build unchanged reviewed source once; reconcile uncertain dispatch by observation."""

from dataclasses import asdict
from datetime import datetime

from application.deployment_core import analyze
from application.infrastructure import inspect_infrastructure
from ports.artifacts import SourceArtifact
from ports.remote_builds import canonical, digest, validate_request, validate_result
from ports.state import RecordConflict


class IncidentSourceBuildExecution:
    def __init__(self, consents, executions, sources, builder, objects, verifier, *, clock):
        self.consents, self.executions, self.sources = consents, executions, sources
        self.builder, self.objects, self.verifier, self.clock = builder, objects, verifier, clock

    def _current(self, actor, job_id, approval_id, options):
        snapshot, approval = self.consents._load(actor, job_id, approval_id, options)
        reviewer = self.consents.reviewer(approval["approved_by"])
        if reviewer != actor:
            from domain.access import Principal, Role

            if (
                not isinstance(reviewer, Principal)
                or reviewer.user_id != approval["approved_by"]
                or reviewer.organization_id != actor.organization_id
                or reviewer.role is not Role.ADMIN
            ):
                raise PermissionError("Current build approver required")
        if (
            approval["revoked_at"] is not None
            or approval["job_digest"] != digest(snapshot.record)
            or approval["metadata_revision"] != snapshot.revision
            or self.consents.settings is None
            or asdict(self.consents.settings) != approval["builder"]
        ):
            raise RecordConflict("Consumed build binding changed")
        return snapshot, approval

    def execute(self, actor, job_id, *, approval_id, **options):
        if self.executions.load(actor, approval_id) is not None:
            raise RecordConflict("Build already reserved; observe without redispatch")
        self.consents.check(actor, job_id, approval_id=approval_id, **options)
        snapshot, approval = self._current(actor, job_id, approval_id, options)
        original = SourceArtifact.from_record(approval["candidate"])
        with self.sources.restore(actor, original) as project:
            if inspect_infrastructure(project).requirements:
                raise ValueError(
                    "New-source build execution currently requires stateless HTTP; preserve resource requirements"
                )
            plan = asdict(analyze(project))
            if plan["required_env"]:
                raise ValueError("Source build needs a separately approved environment binding")
            plan.update(target="aws", replicas=1)
            prepared = self.sources.capture_prepared(
                actor, original, project, expected_digest=original.source_digest
            )
        settings = approval["builder"]
        request = {
            "version": 1,
            "build_id": approval["build_id"],
            "workspace": self.executions.records.workspace,
            "job_id": job_id,
            "created_by": approval["approved_by"],
            "source_ref": prepared.record(),
            "approved_plan_json": canonical(plan).decode(),
            "plan_digest": digest(plan),
            "source_digest": original.source_digest,
            **{
                k: settings[k]
                for k in ["bucket", "account_id", "region", "repository", "workflow_sha", "platform_code_sha"]
            },
        }
        validate_request(request)
        self.consents.check(actor, job_id, approval_id=approval_id, **options)
        if self._current(actor, job_id, approval_id, options)[0] != snapshot:
            raise RecordConflict("Source build changed before reservation")
        current = self.executions.reserve(actor, approval, snapshot, request)
        # A crash before dispatch remains reserved. No automatic replacement or retry.
        self.objects.put_request(request)
        current = self.executions.transition(actor, approval, snapshot, current, "dispatching")
        self._guard(actor, job_id, approval_id, options, current)
        self.builder.dispatch(request)
        current = self.executions.transition(actor, approval, snapshot, current, "waiting")
        return self._report(current)

    def _guard(self, actor, job_id, approval_id, options, expected):
        snapshot, approval = self._current(actor, job_id, approval_id, options)
        current = self.executions.load(actor, approval_id)
        if (
            current is None
            or current.revision != expected.revision
            or current.record != expected.record
            or current.record["approval_digest"] != digest(approval)
        ):
            raise RecordConflict("Build execution changed during observation")
        if datetime.fromisoformat(self.clock()) >= datetime.fromisoformat(current.record["deadline"]):
            raise ValueError("Build execution deadline expired")
        return snapshot, approval

    def observe(self, actor, job_id, *, approval_id, **options):
        current = self.executions.load(actor, approval_id)
        if current is None:
            raise FileNotFoundError("No consumed build consent")
        snapshot, approval = self._guard(actor, job_id, approval_id, options, current)
        if current.record["phase"] in {"reserved", "failed", "verified"}:
            return self._report(current)
        request = current.record["request"]
        run = self.builder.observe(request)
        self._guard(actor, job_id, approval_id, options, current)
        if run is None:
            return self._report(current)
        if not run["succeeded"]:
            current = self.executions.transition(actor, approval, snapshot, current, "failed", run=run)
        else:
            result = validate_result(self.objects.result(request), request, run["run_id"])
            receipt = self.verifier.verify(
                request, result, guard=lambda: self._guard(actor, job_id, approval_id, options, current)
            )
            self._guard(actor, job_id, approval_id, options, current)
            current = self.executions.transition(
                actor, approval, snapshot, current, "verified", run=run, result=result, image_receipt=receipt
            )
        return self._report(current)

    @staticmethod
    def _report(current):
        value = current.record
        return {
            "approval_id": value["approval_id"],
            "build_id": value["request"]["build_id"],
            "phase": value["phase"],
            "execution_revision": current.revision,
            "build_verified": value["phase"] == "verified",
            "dispatch_retry_allowed": False,
            "recovery_authorized": False,
            "hold_released": False,
            "image": value["result"]["image"] if value["result"] else None,
        }
