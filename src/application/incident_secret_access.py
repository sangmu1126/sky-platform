"""Durable app-Secret access denial, without credential activation or release."""

import hashlib
import json
import re
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timedelta
from uuid import uuid4

from application.incident_credential_preparation import FIELD as PREPARATION
from application.incident_credential_preparation import preparation_record_is_valid
from application.incident_database_restriction import FIELD as RESTRICTION
from application.incident_database_restriction import restriction_record_is_valid
from application.incident_runtime_inspection import IncidentRuntimeInspection
from application.security_hold import validate_release_request
from domain.access import Principal, Role
from domain.incident_secret_access import IncidentSecretRegistration, runtime_context, validate_access_target
from ports.state import RecordConflict

FIELD = "security_secret_access_fence"


def access_context(job, registration):
    context = _base_access_context(job, registration)
    history = job.get("security_incident_history", [])
    if not isinstance(history, list) or len(history) > 10:
        raise ValueError("Bounded completed incident history required")
    prior_ids, recovery_ids = set(), set()
    for audit in history:
        if not isinstance(audit, dict) or not isinstance(audit.get("controls"), dict):
            raise TypeError("Completed incident access archive required")
        recovery_id = audit.get("id")
        if (
            not isinstance(recovery_id, str)
            or not re.fullmatch(r"[a-f0-9]{32}", recovery_id)
            or recovery_id in recovery_ids
        ):
            raise ValueError("Unique completed incident recovery identity required")
        recovery_ids.add(recovery_id)
        recovery = audit["controls"].get("security_recovery")
        if (
            not isinstance(recovery, dict)
            or recovery.get("id") != recovery_id
            or recovery.get("phase") != "verified"
            or recovery.get("external_pending") is not False
            or recovery.get("incident_id") != audit.get("incident_id")
            or recovery.get("boundary_id") != audit.get("prior_boundary")
        ):
            raise ValueError("Completed one-shot recovery archive required")
        previous = _base_access_context(
            {**job, **audit["controls"], "result": audit.get("prior_result")}, registration
        )
        if prior_ids:
            previous["prior_role_ids"] = sorted(prior_ids)
        fence = audit["controls"].get(FIELD)
        if (
            not access_record_is_valid(fence, previous)
            or fence["phase"] != "policy_recorded"
            or fence["incident_id"] != audit.get("incident_id")
            or fence["boundary_id"] != audit.get("prior_boundary")
        ):
            raise ValueError("Matching completed incident access fence required")
        prior_ids.update(fence["target"]["roles"].values())
    if prior_ids:
        context["prior_role_ids"] = sorted(prior_ids)
    return context


def _base_access_context(job, registration):
    if not isinstance(registration, IncidentSecretRegistration):
        raise ValueError("Trusted app Secret registration required")  # noqa: TRY004 -- invalid registration/policy contract
    prepared, restricted = job.get(PREPARATION), job.get(RESTRICTION)
    if (
        not preparation_record_is_valid(prepared)
        or prepared["phase"] != "prepared_restricted"
        or not restriction_record_is_valid(restricted)
        or restricted["phase"] != "verified"
        or prepared["restriction_operation_id"] != restricted["operation_id"]
        or any(prepared[key] != restricted[key] for key in ("incident_id", "boundary_id", "binding"))
        or prepared["binding"] != asdict(registration.binding)
        or job.get("workload_database_binding") != prepared["binding"]
        or prepared["resource_id"] != registration.resource_id
    ):
        raise ValueError("Matching registered restricted credential preparation required")
    result = job.get("result")
    runtime = runtime_context(result)
    if (
        not isinstance(result.get("database"), dict)
        or result["database"].get("secret_arn") != registration.secret_arn
        or (runtime["account"], runtime["region"])
        != (registration.binding.account_id, registration.binding.region)
    ):
        raise ValueError("Recorded runtime must use the registered app Secret")
    return {
        "binding": asdict(registration.binding),
        "resource_id": registration.resource_id,
        "secret_arn": registration.secret_arn,
        "kms_key_arn": registration.kms_key_arn,
        "candidate_secret_arn": prepared["candidate_secret_ref"],
        "candidate_version_id": prepared["candidate_version_id"],
        "preparer_principal": prepared["candidate_access_principal"],
        "runtime": runtime,
    }


def context_digest(context):
    return hashlib.sha256(json.dumps(context, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class IncidentSecretAccess:
    def __init__(self, records, registration, adapter, *, clock, revalidate):
        self.scope = IncidentRuntimeInspection(records, None, clock=clock, revalidate=revalidate)
        self.writer, self.registration, self.adapter, self.clock = (
            self.scope.writer,
            registration,
            adapter,
            clock,
        )

    def status(self, principal, job_id):
        if (
            not isinstance(principal, Principal)
            or principal.role is not Role.ADMIN
            or self.scope.revalidate() != principal
        ):
            raise PermissionError("Current organization administrator required")
        snapshot = self.writer.snapshot(principal, job_id)
        record = snapshot.record.get(FIELD)
        if record is None:
            return {"phase": "not_recorded"}
        # Status without a trusted registration deliberately does not expose raw metadata.
        if self.registration is None:
            return {"phase": "registration_required"}
        try:
            context = access_context(snapshot.record, self.registration)
        except (ValueError, TypeError, KeyError):
            return {"phase": "needs_attention", "record_valid": False}
        if not access_record_is_valid(record, context):
            return {"phase": "needs_attention", "record_valid": False}
        return {**deepcopy(record), "record_valid": True}

    def _scope(self, principal, job_id, incident_id, boundary, now):
        snapshot = self.scope._scope(principal, job_id, incident_id, boundary, now)
        context = access_context(snapshot.record, self.registration)
        if (
            snapshot.record[PREPARATION]["incident_id"] != incident_id
            or snapshot.record[PREPARATION]["boundary_id"] != boundary
        ):
            raise ValueError("Credential preparation belongs to a different incident")
        if datetime.fromisoformat(now) < datetime.fromisoformat(snapshot.record[PREPARATION]["prepared_at"]):
            raise ValueError("Access fencing cannot precede credential preparation")
        return snapshot, context

    def fence(self, principal, job_id, *, incident_id, expected_boundary, expected_revision):
        now = self.clock()
        validate_release_request(
            incident_id, "secret-access-fence", expected_revision, expected_boundary, now
        )
        snapshot, context = self._scope(principal, job_id, incident_id, expected_boundary, now)
        previous = snapshot.record.get(FIELD)
        if previous is not None:
            if access_record_is_valid(previous, context) and all(
                previous[key] == value
                for key, value in {
                    "incident_id": incident_id,
                    "boundary_id": expected_boundary,
                    "admitted_revision": expected_revision,
                    "requested_by": principal.user_id,
                }.items()
            ):
                return deepcopy(previous)
            raise ValueError("Existing Secret access fence requires operator inspection")
        if snapshot.revision != expected_revision:
            raise RecordConflict("Deployment changed since Secret access review")

        def before():
            if self._scope(principal, job_id, incident_id, expected_boundary, now) != (snapshot, context):
                raise RecordConflict("Incident changed during Secret access preflight")

        try:
            target = self.adapter.preflight(deepcopy(context), guard=before)
            validate_access_target(target, context)
            before()
        except (PermissionError, RecordConflict):
            raise
        except Exception:  # noqa: BLE001 -- suppress native policy and credential diagnostics
            raise OSError("Secret access preflight unavailable; no policy change requested") from None
        intent = {
            "schema_version": 1,
            "operation_id": uuid4().hex,
            "incident_id": incident_id,
            "boundary_id": expected_boundary,
            "admitted_revision": expected_revision,
            "requested_by": principal.user_id,
            "requested_at": now,
            "context_digest": context_digest(context),
            "target": deepcopy(target),
            "phase": "applying",
        }
        if not access_record_is_valid(intent, context):
            raise ValueError("Exact Secret access fence intent required")
        try:
            admitted = self.writer.patch(
                principal, job_id, expected_revision, {FIELD: intent, "promotion_automation_consent": None}
            )
        except OSError:
            raise OSError(
                "Secret access admission uncertain; inspect persisted intent before proceeding"
            ) from None

        def guard():
            current, current_context = self._scope(principal, job_id, incident_id, expected_boundary, now)
            if (
                current.revision != admitted.revision
                or current.record.get(FIELD) != intent
                or current_context != context
            ):
                raise RecordConflict("Secret access fencing execution ownership changed")
            return current

        try:
            guard()
            receipt = self.adapter.fence(deepcopy(context), deepcopy(target), guard=guard)
            if any(
                receipt.get(key) is not value
                for key, value in {
                    "policy_document_verified": True,
                    "iam_propagation_verified": False,
                    "secret_value_read": False,
                    "role_policies_changed": False,
                }.items()
            ) or receipt != {
                "target": target,
                "policy_document_verified": True,
                "iam_propagation_verified": False,
                "secret_value_read": False,
                "role_policies_changed": False,
            }:
                raise ValueError("Exact app Secret policy receipt required")
            done = {**intent, "phase": "policy_recorded", "recorded_at": self.clock()}
            if not access_record_is_valid(done, context):
                raise ValueError("Invalid Secret access policy acknowledgement")
            current = guard()
            self.writer.patch(principal, job_id, current.revision, {FIELD: done})
            return deepcopy(done)
        except Exception:  # noqa: BLE001 -- retain uncertainty without replay or removing protection
            try:
                current = guard()
                self.writer.patch(
                    principal,
                    job_id,
                    current.revision,
                    {FIELD: {**intent, "phase": "needs_attention", "failure_code": "outcome_unconfirmed"}},
                )
            except Exception:  # noqa: BLE001,S110 -- keep durable applying intent if state is unavailable
                pass
            raise OSError("Secret access outcome needs inspection; no automatic replay or release") from None

    def inspect(
        self, principal, job_id, *, incident_id, expected_boundary, expected_revision, expected_operation_id
    ):
        started = self.clock()
        validate_release_request(
            incident_id, "secret-access-inspection", expected_revision, expected_boundary, started
        )
        snapshot, context = self._scope(principal, job_id, incident_id, expected_boundary, started)
        record = snapshot.record.get(FIELD)
        if (
            not access_record_is_valid(record, context)
            or record["operation_id"] != expected_operation_id
            or record["incident_id"] != incident_id
            or record["boundary_id"] != expected_boundary
            or datetime.fromisoformat(started) < datetime.fromisoformat(record["requested_at"])
        ):
            raise ValueError("Exact current Secret access fencing operation required")
        if snapshot.revision != expected_revision:
            raise RecordConflict("Deployment changed since Secret access inspection request")

        def guard():
            if self._scope(principal, job_id, incident_id, expected_boundary, started) != (snapshot, context):
                raise RecordConflict("Incident changed during Secret access inspection")

        try:
            guard()
            receipt = self.adapter.inspect(deepcopy(context), deepcopy(record["target"]), guard=guard)
            expected = {
                "target": record["target"],
                "policy_state": receipt.get("policy_state"),
                "candidate_protected": True,
                "read_only": True,
                "state_changed": False,
                "iam_propagation_verified": False,
                "cached_credentials_erased": False,
                "execution_exclusion_verified": False,
                "recovery_authorized": False,
            }
            if (
                any(receipt.get(key) is not value for key, value in expected.items() if type(value) is bool)
                or receipt != expected
                or receipt["policy_state"]
                not in {
                    "runtime_roles_denied",
                    "not_recorded",
                    "review_required",
                }
            ):
                raise ValueError("Exact read-only Secret access receipt required")
            checked = datetime.fromisoformat(self.clock())
            beginning = datetime.fromisoformat(started)
            if checked.tzinfo is None or not beginning <= checked <= beginning + timedelta(seconds=300):
                raise ValueError("Fresh Secret access inspection required")
            guard()
        except (PermissionError, RecordConflict):
            raise
        except Exception:  # noqa: BLE001 -- never leak provider policy details
            raise OSError("Secret access inspection unavailable; no mutation requested") from None
        return {
            "operation_id": expected_operation_id,
            "metadata_revision": snapshot.revision,
            "persisted_phase": record["phase"],
            "observed_at": checked.isoformat(),
            **deepcopy(receipt),
        }


def access_record_is_valid(record, context):
    base = {
        "schema_version",
        "operation_id",
        "incident_id",
        "boundary_id",
        "admitted_revision",
        "requested_by",
        "requested_at",
        "context_digest",
        "target",
        "phase",
    }
    extra = {"applying": set(), "needs_attention": {"failure_code"}, "policy_recorded": {"recorded_at"}}
    try:
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("phase"), str)
            or record["phase"] not in extra
        ):
            return False
        if (
            set(record) != base | extra[record["phase"]]
            or type(record["schema_version"]) is not int
            or record["schema_version"] != 1
        ):
            return False
        validate_release_request(
            record["incident_id"],
            "secret-access-fence",
            record["admitted_revision"],
            record["boundary_id"],
            record["requested_at"],
        )
        validate_access_target(record["target"], context)
        if (
            record["context_digest"] != context_digest(context)
            or not isinstance(record["operation_id"], str)
            or not re.fullmatch(r"[a-f0-9]{32}", record["operation_id"])
            or not isinstance(record["requested_by"], str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", record["requested_by"])
        ):
            return False
        if record["phase"] == "needs_attention":
            return record["failure_code"] == "outcome_unconfirmed"
        if record["phase"] == "policy_recorded":
            stamp = datetime.fromisoformat(record["recorded_at"])
            return stamp.tzinfo is not None and stamp >= datetime.fromisoformat(record["requested_at"])
        return True
    except (ValueError, TypeError, KeyError):
        return False
