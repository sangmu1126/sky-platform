"""Consume one admitted operation; never redispatch an uncertain remote build."""

import threading
import time
from contextlib import contextmanager

from ports.remote_builds import digest, request_for, validate_result


class OwnershipLost(OSError):
    pass


class BuildConsumer:
    def __init__(
        self,
        store,
        queue,
        builder,
        objects,
        verifier,
        settings,
        protection,
        owner,
        *,
        poll_seconds=5,
        timeout_seconds=2700,
        heartbeat_seconds=30,
        clock=time.monotonic,
        deployer=None,
        deployment_timeout_seconds=1800,
        execution_grants=None,
    ):
        self.execution_grants = execution_grants
        self.store, self.queue, self.builder, self.objects = store, queue, builder, objects
        self.deployer, self.deployment_timeout_seconds = deployer, deployment_timeout_seconds
        self.verifier, self.settings, self.protection, self.owner = verifier, settings, protection, owner
        self.poll_seconds, self.timeout_seconds, self.heartbeat_seconds, self.clock = (
            poll_seconds,
            timeout_seconds,
            heartbeat_seconds,
            clock,
        )

    @contextmanager
    def ownership(self, lease, delivery, request=None):
        stop, lost = threading.Event(), threading.Event()

        def guard():
            if lost.is_set() or not self.store.heartbeat(lease, seconds=90):
                raise OwnershipLost("Build ownership lost")

        def renew():
            if self.execution_grants is not None:
                if request is None:
                    raise ValueError("Current immutable build request required for delegation")
                self.execution_grants.renew(request, lease, guard=guard)

        def heartbeat():
            while not stop.wait(self.heartbeat_seconds):
                try:
                    guard()
                    renew()
                    self.queue.extend(delivery, seconds=300)
                    self.protection.set(True)
                except (OSError, ValueError):
                    lost.set()
                    return

        thread = threading.Thread(target=heartbeat, daemon=True)
        try:
            thread.start()
            yield guard
        finally:
            stop.set()
            if thread.ident is not None:
                thread.join(timeout=30)
            if self.execution_grants is not None and request is not None:
                try:
                    self.execution_grants.revoke(request, lease)
                except (OSError, ValueError):
                    pass  # The existing delegation still expires within 45s.

    def consume_once(self, stop=None):
        stop = stop or threading.Event()
        self.store.recover_expired(limit=10)
        delivery = self.queue.receive()
        if delivery is None:
            return "idle"
        message = delivery.message
        if message is None or message["workspace"] != self.store.workspace:
            self.queue.extend(delivery, seconds=60)
            return "invalid"
        operation = self.store.get(message["operation_id"])
        if operation.application_id != message["application_id"]:
            self.queue.extend(delivery, seconds=60)
            return "invalid"
        if operation.attempt_id != message["attempt_id"] or operation.status in {
            "failed",
            "succeeded",
            "needs_attention",
        }:
            self.queue.delete(delivery)
            return "duplicate"
        if operation.status == "running":
            self.queue.extend(delivery, seconds=30)
            return "busy"
        request = request_for(operation, self.store.workspace, self.settings)
        checkpoint = (
            operation.checkpoint
            if operation.checkpoint.get("stage") in {"build_ready", "build_failed", "deployed"}
            else {"stage": "building", "request": request, "request_digest": digest(request)}
        )
        self.protection.set(True)
        try:
            lease = self.store.claim(operation.id, operation.attempt_id, self.owner, seconds=90)
            if lease is None:
                self.queue.extend(delivery, seconds=30)
                return "busy"
            with self.ownership(lease, delivery, request) as guard:
                try:
                    guard()
                    if not self.store.build_progress(lease, checkpoint, stage="building"):
                        raise OwnershipLost()
                    saved = operation.checkpoint
                    if saved.get("stage") in {"build_ready", "build_failed", "deployed"}:
                        if saved.get("request_digest") != digest(request):
                            raise ValueError("Recovered build request changed")
                        run = self.builder.observe(request)
                        if run != saved.get("verified_run"):
                            raise ValueError("Recovered workflow evidence changed")
                        if saved["stage"] in {"build_ready", "deployed"}:
                            result = validate_result(saved["build_result"], request, run["run_id"])
                            self.verifier.verify(request, result)
                            if self.deployer is not None:
                                if saved["stage"] == "deployed":
                                    current = self.deployer.observe(saved["deployment_intent"])
                                    if current != saved["deployment_result"]:
                                        raise ValueError("Recovered deployment observation changed")
                                    if not self.store.deployment_complete(lease, saved, current):
                                        raise OwnershipLost()
                                    self.queue.delete(delivery)
                                    return "succeeded"
                                from application.built_deployment import (
                                    deploy_built_image,
                                )

                                return deploy_built_image(self, lease, request, saved, guard, stop, delivery)
                        if not self.store.build_progress(
                            lease,
                            saved,
                            stage=("build_ready" if saved["stage"] == "build_ready" else "failed"),
                        ):
                            raise OwnershipLost()
                        self.queue.delete(delivery)
                        return "build_ready" if saved["stage"] == "build_ready" else "failed"
                    if saved and (
                        saved.get("stage") != "building" or saved.get("request_digest") != digest(request)
                    ):
                        raise ValueError("Build checkpoint requires explicit reconciliation")
                    intent = {
                        "kind": "github_build",
                        "build_id": request["build_id"],
                        "request_digest": digest(request),
                        "repository": self.settings.repository,
                        "workflow_sha": self.settings.workflow_sha,
                    }
                    if not self.store.begin_external(lease, intent):
                        raise OwnershipLost()
                    self.objects.put_request(request)
                    guard()
                    if self.execution_grants is not None:
                        self.execution_grants.renew(request, lease, guard=guard)
                    self.builder.dispatch(request)
                    checkpoint["stage"] = "waiting_build"
                    if not self.store.build_progress(lease, checkpoint, stage="waiting_build"):
                        raise OwnershipLost()
                    until = self.clock() + self.timeout_seconds
                    while not stop.is_set() and self.clock() < until:
                        guard()
                        try:
                            run = self.builder.observe(request)
                            if run is not None:
                                if not run["succeeded"]:
                                    checkpoint.update(stage="build_failed", verified_run=run)
                                    if not self.store.observe_external(lease, run, checkpoint):
                                        raise OwnershipLost()
                                    if not self.store.build_progress(
                                        lease, {**checkpoint, "reason": "remote_build_failed"}, stage="failed"
                                    ):
                                        raise OwnershipLost()
                                    self.queue.delete(delivery)
                                    return "failed"
                                result = validate_result(self.objects.result(request), request, run["run_id"])
                                verification = self.verifier.verify(request, result)
                                if (
                                    isinstance(verification, dict)
                                    and verification.get("measured_build_usage") is not None
                                ):
                                    usage = verification["measured_build_usage"]
                                    self.store.settle_external_usage(
                                        lease,
                                        {"requests": 1, "build_seconds": usage["build_seconds"]},
                                        digest(usage),
                                    )
                                guard()
                                checkpoint.update(
                                    stage="build_ready",
                                    build_result=result,
                                    verified_run=run,
                                    reason="deployment_executor_required",
                                )
                                if not self.store.observe_external(lease, run, checkpoint):
                                    raise OwnershipLost()
                                if self.deployer is not None:
                                    from application.built_deployment import (
                                        deploy_built_image,
                                    )

                                    return deploy_built_image(
                                        self, lease, request, checkpoint, guard, stop, delivery
                                    )
                                if not self.store.build_progress(lease, checkpoint, stage="build_ready"):
                                    raise OwnershipLost()
                                self.queue.delete(delivery)
                                return "build_ready"
                        except OwnershipLost:
                            raise
                        except OSError:
                            if checkpoint.get("stage") in {"deploying", "deployed"}:
                                raise
                            # Read failures after dispatch never trigger a second workflow.
                        stop.wait(self.poll_seconds)
                    guard()
                    if self.store.build_progress(
                        lease,
                        {**checkpoint, "reason": "build_observation_incomplete"},
                        stage="needs_attention",
                    ):
                        self.queue.delete(delivery)
                    return "needs_attention"
                except OwnershipLost:
                    return "ownership_lost"
                except (OSError, ValueError):
                    guard()
                    # Includes uncertain dispatch/commit. Preserve request intent and app lock.
                    reason = (
                        "deployment_requires_reconciliation"
                        if checkpoint.get("stage") in {"deploying", "deployed"}
                        else "build_requires_reconciliation"
                    )
                    if self.store.build_progress(
                        lease, {**checkpoint, "reason": reason}, stage="needs_attention"
                    ):
                        self.queue.delete(delivery)
                    return "needs_attention"
        finally:
            try:
                self.protection.set(False)
            except OSError:
                pass
