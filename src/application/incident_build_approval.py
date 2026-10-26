"""Compare KMS build claims with the held job's authoritative admission ledger."""

from copy import deepcopy
from datetime import datetime, timedelta

from application.incident_runtime_inspection import IncidentRuntimeInspection
from application.kms_build_signature import ALGORITHM, verify_build_signature
from application.security_hold import validate_release_request
from domain.incident_runtime import runtime_identity
from ports.remote_builds import digest
from ports.state import RecordConflict


class IncidentBuildApprovalInspection:
    def __init__(self, records, approvals, identity, *, clock, revalidate, key_observer=None):
        self.scope = IncidentRuntimeInspection(records, None, clock=clock, revalidate=revalidate)
        self.approvals, self.identity, self.clock = approvals, identity, clock
        self.key_observer = key_observer

    def inspect(
        self,
        principal,
        job_id,
        *,
        incident_id,
        expected_boundary,
        expected_revision,
        bundle,
        image_digest,
        config_digest,
        run_id,
    ):
        started = self.clock()
        validate_release_request(incident_id, "build-approval", expected_revision, expected_boundary, started)
        original = self.scope._scope(principal, job_id, incident_id, expected_boundary, started)
        if original.revision != expected_revision:
            raise RecordConflict("Deployment changed since build approval inspection request")

        def guard():
            if self.scope._scope(principal, job_id, incident_id, expected_boundary, started) != original:
                raise RecordConflict("Incident or deployment changed during build approval inspection")

        try:
            guard()
            request = self.approvals.expected_request(principal, deepcopy(original.record))
            guard()
            account, region, *_ = runtime_identity(original.record.get("result"))
            if (request["account_id"], request["region"]) != (account, region) or (
                self.identity.account_id,
                self.identity.region,
            ) != (account, region):
                raise ValueError("Signing and admission scopes differ from held runtime")
            receipt = verify_build_signature(
                deepcopy(bundle),
                self.identity,
                request,
                image_digest=image_digest,
                config_digest=config_digest,
                run_id=run_id,
                now=datetime.fromisoformat(self.clock()),
            )
            guard()
            key_observation = None
            if self.key_observer is not None:
                key_observation = self.key_observer.observe(guard=guard)
                guard()
            if self.approvals.expected_request(principal, deepcopy(original.record)) != request:
                raise RecordConflict("Admission ledger changed during build approval inspection")
            guard()
            completed = datetime.fromisoformat(self.clock())
            if (
                not datetime.fromisoformat(started)
                <= completed
                <= datetime.fromisoformat(started) + timedelta(seconds=300)
            ):
                raise ValueError("Fresh build approval inspection required")
            if self.key_observer is not None:
                validate_key_observation(key_observation, self.identity, started, completed)
            # A short-lived signature may expire while the second DB read runs.
            # Evaluate validity again at the observation's completion time.
            receipt = verify_build_signature(
                deepcopy(bundle),
                self.identity,
                request,
                image_digest=image_digest,
                config_digest=config_digest,
                run_id=run_id,
                now=completed,
            )
            guard()
        except (PermissionError, RecordConflict):
            raise
        except Exception:  # noqa: BLE001 -- no provider diagnostics or stored source in output
            raise OSError("Build approval inspection unavailable; hold and access unchanged") from None
        return {
            **receipt,
            "incident_id": incident_id,
            "boundary_id": expected_boundary,
            "metadata_revision": expected_revision,
            "observed_at": completed.isoformat(),
            "request_digest": digest(request),
            "consumed_deployment_approval_matched": True,
            "current_approval_verified": False,
            "recovery_authorized": False,
            "ecr_image_verified": False,
            "state_changed": False,
            "read_only": True,
            **(
                {"key_liveness_checked": True, "signing_key": deepcopy(key_observation)}
                if self.key_observer is not None
                else {}
            ),
        }


def validate_key_observation(value, identity, started, completed):
    expected = {
        "key_arn": identity.key_arn,
        "public_key_fingerprint": identity.fingerprint,
        "algorithm": ALGORITHM,
        "key_state": "Enabled",
        "key_liveness_checked": True,
        "read_only": True,
        "state_changed": False,
        "revocation_race_excluded": False,
        "key_policy_audited": False,
        "recovery_authorized": False,
    }
    if (
        not isinstance(value, dict)
        or set(value) != set(expected) | {"observed_at"}
        or any(type(value.get(k)) is not type(v) or value[k] != v for k, v in expected.items())
    ):
        raise ValueError("Exact limited key-state observation required")
    observed = datetime.fromisoformat(value["observed_at"])
    if observed.tzinfo is None or not datetime.fromisoformat(started) <= observed <= completed:
        raise ValueError("Fresh signing key observation required")
