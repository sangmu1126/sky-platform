"""Observe an uncertain deployment once; never repeat build or AWS submission."""

from application.deployment_writes import DeploymentMetadataWriter
from domain.access import Principal, Role
from ports.remote_builds import digest, request_for, validate_result


class BuildDeploymentReconciliation:
    def __init__(self, store, builder, verifier, deployer, settings, *, revalidate):
        self.store, self.builder, self.verifier, self.deployer = store, builder, verifier, deployer
        self.settings, self.revalidate = settings, revalidate

    def observe(self, principal, operation_id, *, expected_version, executor_stopped):
        if (
            not isinstance(principal, Principal)
            or principal.role is not Role.ADMIN
            or self.revalidate() != principal
            or executor_stopped is not True
        ):
            raise PermissionError("Current administrator and stopped original executor required")
        operation = self.store.get(operation_id)
        if (
            operation.kind != "deploy"
            or operation.status != "needs_attention"
            or operation.row_version != expected_version
        ):
            raise ValueError("Exact unresolved deployment operation required")
        checkpoint = operation.checkpoint
        request = request_for(operation, self.store.workspace, self.settings)
        snapshot = DeploymentMetadataWriter(self.store.records).snapshot(principal, request["job_id"])
        if (
            snapshot.record.get("security_hold") is not None
            or snapshot.record.get("security_database_restriction") is not None
            or checkpoint.get("stage") != "deploying"
            or not operation.external_pending
            or checkpoint.get("request_digest") != digest(request)
            or operation.external_intent != checkpoint.get("deployment_intent")
            or checkpoint["deployment_intent"].get("request_digest") != digest(request)
        ):
            raise ValueError("Pending deployment intent and unchanged approval are required")
        run = self.builder.observe(request)
        if run != checkpoint.get("verified_run") or run.get("succeeded") is not True:
            raise ValueError("Original successful workflow observation changed")
        built = validate_result(checkpoint["build_result"], request, run["run_id"])
        self.verifier.verify(request, built)
        from application.built_deployment import bound_deployer

        def guard():
            if (
                self.revalidate() != principal
                or self.store.get(operation_id) != operation
                or self.store.records.load_job(request["job_id"]) != snapshot
            ):
                raise PermissionError("Reconciliation authority or application changed")

        result = bound_deployer(self.deployer, request, guard).observe(checkpoint["deployment_intent"])
        if result is None:
            return {"status": "pending", "state_changed": False, "resubmission": False}
        if self.revalidate() != principal:
            raise PermissionError("Administrator changed during observation")
        if (
            self.store.get(operation_id) != operation
            or self.store.records.load_job(request["job_id"]) != snapshot
        ):
            raise ValueError("Deployment changed during observation")
        self.store.reconcile_deployment(principal, operation, snapshot, result)
        return {
            "status": "succeeded",
            "state_changed": True,
            "resubmission": False,
            "operation_id": operation.id,
            "url": result["url"],
        }
