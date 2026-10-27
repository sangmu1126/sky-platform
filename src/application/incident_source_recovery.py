"""Separate recovery consent for a verified new build, preserving the old hold."""

import json
import re
from copy import deepcopy
from datetime import datetime, timedelta

from application.security_hold import validate_release_request
from ports.remote_builds import digest
from ports.state import RecordConflict


class IncidentSourceRecovery:
    def __init__(
        self,
        build_execution,
        store,
        runtime,
        *,
        clock,
        profile="stateless-http",
        prerequisites=None,
        retirement=None,
    ):
        if profile not in {"stateless-http", "postgresql"}:
            raise ValueError("Registered recovery profile required")
        self.build_execution, self.store, self.runtime = build_execution, store, runtime
        self.clock, self.profile, self.prerequisites, self.retirement = (
            clock,
            profile,
            prerequisites,
            retirement,
        )

    def _current(self, actor, job_id, approval_id, options):
        snapshot, approval = self.build_execution._current(actor, job_id, approval_id, options)
        build = self.build_execution.executions.load(actor, approval_id)
        if build is None or build.record["phase"] != "verified":
            raise ValueError("Verified new-source build required")
        # Consumed build observation is allowed after original review expiry;
        # source identity, revocation and the separate execution window still apply.
        self.build_execution._guard(actor, job_id, approval_id, options, build)
        return snapshot, approval, build

    def _image(self, actor, job_id, approval_id, options, build):
        request = build.record["request"]
        run = self.build_execution.builder.observe(request)
        if run != build.record["run"]:
            raise ValueError("Current pinned workflow differs from verified build")
        self.build_execution.verifier.verify(
            request,
            build.record["result"],
            guard=lambda: self.build_execution._guard(actor, job_id, approval_id, options, build),
        )

    def _prerequisites(self, actor, job_id, snapshot, build, options):
        plan = json.loads(build.record["request"]["approved_plan_json"])
        requirements = set(plan.get("infrastructure_profile", {}).get("requirements", []))
        prior_db = snapshot.record.get("workload_database_binding") or (
            snapshot.record.get("result") or {}
        ).get("database")
        if self.profile == "postgresql":
            engines = set(plan.get("infrastructure_profile", {}).get("database_engines", []))
            if (
                self.prerequisites is None
                or requirements - {"database"}
                or engines - {"postgresql"}
                or ("database" in requirements and engines != {"postgresql"})
            ):
                raise ValueError("Registered PostgreSQL path cannot erase unsupported app requirements")
            self.prerequisites._current(actor, job_id, options)
            verification = snapshot.record.get("security_database_verification", {})
            receipt = verification.get("receipt", {})
            if (
                verification.get("phase") != "verified_restricted"
                or any(
                    receipt.get(k) is not True
                    for k in ["baseline_matched", "authentication_verified", "previous_password_rejected"]
                )
                or receipt.get("login_enabled") is not False
                or receipt.get("credentials_activated") is not False
            ):
                raise ValueError("Restricted verified database candidate required")
        else:
            db_controls = any(
                snapshot.record.get(k) is not None
                for k in (
                    "security_database_restriction",
                    "security_credential_preparation",
                    "security_database_verification",
                    "security_secret_access_fence",
                )
            )
            if requirements or prior_db or db_controls or plan.get("required_env"):
                raise ValueError("Stateless recovery cannot discard database, environment or storage needs")
            if snapshot.record.get("result") is not None:
                if self.retirement is None:
                    raise ValueError("Old runtime must be retired and freshly inspected")
                receipt = self.retirement.inspect(actor, job_id, **options)
                if receipt.get("registered_runtime_retirement_verified") is not True:
                    raise ValueError("Old runtime retirement not verified")

    def approve(
        self,
        actor,
        job_id,
        *,
        approval_id,
        recovery_id,
        review_ref,
        seconds=900,
        public_access=False,
        **options,
    ):
        started = self.clock()
        validate_release_request(
            options["incident_id"],
            review_ref,
            options["expected_revision"],
            options["expected_boundary"],
            started,
        )
        if (
            not isinstance(recovery_id, str)
            or not re.fullmatch(r"[a-f0-9]{32}", recovery_id)
            or type(seconds) is not int
            or not 1 <= seconds <= 900
            or type(public_access) is not bool
        ):
            raise ValueError("Bounded explicit recovery consent required")
        snapshot, approval, build = self._current(actor, job_id, approval_id, options)
        self._prerequisites(actor, job_id, snapshot, build, options)
        self._image(actor, job_id, approval_id, options, build)
        guard = lambda: self._same(actor, job_id, approval_id, options, snapshot, build)
        plan = self.runtime.preflight(
            snapshot.record, recovery_id, build.record, public_access=public_access, guard=guard
        )
        if plan.get("image") != build.record["result"]["image"]:
            raise ValueError("Recovery plan image differs from the verified new build")
        guard()
        now = datetime.fromisoformat(self.clock())
        if (
            not datetime.fromisoformat(started)
            <= now
            <= datetime.fromisoformat(started) + timedelta(seconds=300)
        ):
            raise ValueError("Fresh recovery preflight required")
        value = {
            "version": 1,
            "scope": "new_source_recovery_only",
            "approval_id": approval_id,
            "recovery_id": recovery_id,
            "profile": self.profile,
            "job_id": job_id,
            "organization_id": actor.organization_id,
            "incident_id": options["incident_id"],
            "boundary_id": options["expected_boundary"],
            "approved_by": actor.user_id,
            "review_ref": review_ref,
            "approved_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=seconds)).isoformat(),
            "phase": "approved",
            "build_digest": digest(build.record),
            "plan": deepcopy(plan),
            "plan_digest": digest(plan),
            "result": None,
        }
        return self._report(self.store.approve(actor, approval, snapshot, build, value))

    def _same(self, actor, job_id, approval_id, options, snapshot, build):
        current, _, fresh = self._current(actor, job_id, approval_id, options)
        if current != snapshot or fresh != build:
            raise RecordConflict("Recovery inputs changed")

    def execute(self, actor, job_id, *, approval_id, recovery_id, **options):
        snapshot, approval, build = self._current(actor, job_id, approval_id, options)
        current = self.store.load(actor, approval_id)
        if (
            current is None
            or current.record["phase"] != "approved"
            or current.record["recovery_id"] != recovery_id
        ):
            raise ValueError("Unused exact recovery consent required; inspect instead of replay")
        value = current.record
        if value["profile"] != self.profile:
            raise ValueError("Recovery profile differs from approval")

        def guard():
            self._same(actor, job_id, approval_id, options, snapshot, build)
            reviewer = self.build_execution.consents.reviewer(value["approved_by"])
            from domain.access import Principal, Role

            if (
                not isinstance(reviewer, Principal)
                or reviewer.user_id != value["approved_by"]
                or reviewer.organization_id != actor.organization_id
                or reviewer.role is not Role.ADMIN
            ):
                raise PermissionError("Recovery approver must remain an administrator")
            if datetime.fromisoformat(self.clock()) >= datetime.fromisoformat(value["expires_at"]):
                raise ValueError("Recovery consent expired")
            actual = self.store.load(actor, approval_id)
            if actual != current:
                raise RecordConflict("Recovery ownership changed")

        guard()
        self._prerequisites(actor, job_id, snapshot, build, options)
        self._image(actor, job_id, approval_id, options, build)
        planned = self.runtime.preflight(
            snapshot.record,
            recovery_id,
            build.record,
            public_access=value["plan"]["public_access"],
            guard=guard,
        )
        if planned != value["plan"] or digest(planned) != value["plan_digest"]:
            raise ValueError("Runtime configuration changed since recovery consent")
        current = self.store.transition(actor, approval, snapshot, build, current, "running")
        completion_started = False
        try:
            result = self.runtime.execute(current.record["plan"], guard=guard)
            guard()
            self._image(actor, job_id, approval_id, options, build)
            current = self.store.transition(
                actor, approval, snapshot, build, current, "verified", result=result
            )
            guard()
            completion_started = True
            current = self.store.complete(actor, approval, snapshot, build, current)
            return self._report(current)
        except Exception:  # noqa: BLE001 -- preserve uncertainty, never disclose native secrets
            if completion_started:
                raise OSError(
                    "Recovery commit outcome uncertain; inspect without stopping a possibly committed app"
                ) from None
            # Claim compensation before issuing a stop. A concurrent verified
            # publication must never be stopped by an obsolete executor.
            try:
                actual = self.store.load(actor, approval_id)
                if actual and actual.record["phase"] == "recovered":
                    return self._report(actual)
                if actual and actual.record["phase"] in {"running", "verified"}:
                    self.store.transition(actor, approval, snapshot, build, actual, "needs_attention")
                    self.runtime.restrict(value["plan"])
            except Exception:  # noqa: BLE001,S110 -- retain uncertainty; no unsafe retry or native diagnostics
                pass
            raise OSError("Source recovery requires inspection; hold retained, no automatic replay") from None

    def finalize(self, actor, job_id, *, approval_id, recovery_id, **options):
        snapshot, approval, build = self._current(actor, job_id, approval_id, options)
        current = self.store.load(actor, approval_id)
        if (
            current is None
            or current.record["phase"] not in {"verified", "running"}
            or current.record["recovery_id"] != recovery_id
        ):
            raise ValueError("Exact verified unpublished recovery required")
        value = current.record
        if value["phase"] == "running" and self.profile != "stateless-http":
            raise ValueError("Interrupted database activation requires separate inspection")
        if value["profile"] != self.profile:
            raise ValueError("Recovery publication profile differs")

        def guard():
            self._same(actor, job_id, approval_id, options, snapshot, build)
            reviewer = self.build_execution.consents.reviewer(value["approved_by"])
            from domain.access import Principal, Role

            if (
                not isinstance(reviewer, Principal)
                or reviewer.user_id != value["approved_by"]
                or reviewer.organization_id != actor.organization_id
                or reviewer.role is not Role.ADMIN
                or datetime.fromisoformat(self.clock()) >= datetime.fromisoformat(value["expires_at"])
                or self.store.load(actor, approval_id) != current
            ):
                raise RecordConflict("Recovery publication changed or expired")

        guard()
        self._image(actor, job_id, approval_id, options, build)
        result = self.runtime.observe_verified(value["plan"], value["result"] or {}, guard=guard)
        guard()
        current = self.store.transition(actor, approval, snapshot, build, current, "verified", result=result)
        guard()
        try:
            return self._report(self.store.complete(actor, approval, snapshot, build, current))
        except Exception:  # noqa: BLE001 -- uncertain commit must never stop or recreate an app
            raise OSError(
                "Recovery publication outcome uncertain; inspect without replaying runtime"
            ) from None

    def inspect(self, actor, job_id, *, approval_id, recovery_id, **options):
        value = self.store.load(actor, approval_id)
        if (
            value is None
            or value.record["recovery_id"] != recovery_id
            or value.record.get("job_id") != job_id
            or value.record.get("organization_id") != actor.organization_id
            or value.record.get("incident_id") != options["incident_id"]
            or value.record.get("boundary_id") != options["expected_boundary"]
        ):
            raise FileNotFoundError("Exact source recovery not found")
        if value.record["phase"] == "recovered":
            # Lost final acknowledgement: authenticate against current ownership,
            # not a hold that was atomically archived by completion.
            snapshot = self.build_execution.consents.reviews.scope.writer.snapshot(actor, job_id)
            approval = self.build_execution.consents.ledger.load(actor, approval_id)
            if (
                approval["job_id"] != job_id
                or snapshot.record.get("recovery_build_approval_id") != approval_id
                or snapshot.revision < value.record["completed_metadata_revision"]
            ):
                raise ValueError("Recovered publication differs from current job")
        else:
            self.build_execution.consents._load(actor, job_id, approval_id, options)
        return self._report(value)

    @staticmethod
    def _report(current):
        v = current.record
        return {
            "recovery_id": v["recovery_id"],
            "approval_id": v["approval_id"],
            "phase": v["phase"],
            "hold_released": v["phase"] == "recovered",
            "automation_reenabled": False,
            "execution_retry_allowed": False,
            "url": v["result"].get("url") if v.get("result") else None,
        }
