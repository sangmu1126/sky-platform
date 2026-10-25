"""Incident-bound image inspection without credential activation or recovery approval."""

from datetime import datetime, timedelta

from application.incident_runtime_inspection import IncidentRuntimeInspection
from application.security_hold import validate_release_request
from domain.incident_runtime import runtime_identity
from domain.recovery_image import RecoveryImageRegistration
from ports.state import RecordConflict


class RecoveryImageInspection:
    def __init__(self, records, registration, inspector, *, clock, revalidate):
        self.scope = IncidentRuntimeInspection(
            records, None, clock=clock, revalidate=revalidate
        )
        self.registration, self.inspector, self.clock = registration, inspector, clock

    def inspect(
        self, principal, job_id, *, incident_id, expected_boundary, expected_revision
    ):
        started = self.clock()
        validate_release_request(
            incident_id, "recovery-image", expected_revision, expected_boundary, started
        )
        snapshot = self.scope._scope(
            principal, job_id, incident_id, expected_boundary, started
        )
        if snapshot.revision != expected_revision:
            raise RecordConflict(
                "Deployment changed since recovery image inspection request"
            )
        r = self.registration
        account, region, *_ = runtime_identity(snapshot.record.get("result"))
        if not isinstance(r, RecoveryImageRegistration) or (
            r.organization_id,
            r.application_id,
            r.job_id,
            r.incident_id,
            r.boundary_id,
            r.account_id,
            r.region,
        ) != (
            principal.organization_id,
            snapshot.record.get("application_id"),
            job_id,
            incident_id,
            expected_boundary,
            account,
            region,
        ):
            raise ValueError("Recovery registration differs from held deployment")

        def guard():
            if (
                self.scope._scope(
                    principal, job_id, incident_id, expected_boundary, started
                )
                != snapshot
            ):
                raise RecordConflict(
                    "Incident or deployment changed during image inspection"
                )

        try:
            guard()
            receipt = self.inspector.inspect(r, guard=guard)
            if (
                not isinstance(receipt, dict)
                or set(receipt)
                != {
                    "image",
                    "config_digest",
                    "manifest_bytes_verified",
                    "config_descriptor_verified",
                    "source_provenance_verified",
                    "image_safety_verified",
                    "recovery_authorized",
                    "state_changed",
                    "read_only",
                    "observed_at",
                }
                or receipt["image"] != r.image
                or receipt["config_digest"] != r.config_digest
                or any(
                    receipt[k] is not True
                    for k in (
                        "read_only",
                        "manifest_bytes_verified",
                        "config_descriptor_verified",
                    )
                )
                or any(
                    receipt[k] is not False
                    for k in (
                        "source_provenance_verified",
                        "image_safety_verified",
                        "recovery_authorized",
                        "state_changed",
                    )
                )
            ):
                raise ValueError("Exact limited read-only image receipt required")
            checked, completed = (
                datetime.fromisoformat(receipt["observed_at"]),
                datetime.fromisoformat(self.clock()),
            )
            if (
                checked.tzinfo is None
                or completed.tzinfo is None
                or not (
                    datetime.fromisoformat(started)
                    <= checked
                    <= completed
                    <= datetime.fromisoformat(started) + timedelta(seconds=300)
                )
            ):
                raise ValueError("Fresh image inspection required")
            guard()
        except (PermissionError, RecordConflict):
            raise
        except Exception:  # noqa: BLE001 -- no native diagnostics or credentials in output
            raise OSError(
                "Recovery image inspection unavailable; hold and access unchanged"
            ) from None
        return {
            "incident_id": incident_id,
            "boundary_id": expected_boundary,
            "metadata_revision": snapshot.revision,
            "operator_declared_source": {
                "revision": r.source_revision,
                "digest": r.source_digest,
                "build_reference": r.build_reference,
            },
            **receipt,
        }
