"""Durable credential preparation intent while incident access stays blocked.

Never releases a hold, changes app Secret references or enables LOGIN. An
uncertain external outcome requires inspection, not automatic replay/takeover.
"""

import re
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime
from uuid import uuid4

from application.incident_database_restriction import FIELD as RESTRICTION_FIELD
from application.incident_database_restriction import IncidentDatabaseRestriction, restriction_record_is_valid
from application.security_hold import validate_release_request
from domain.database import DatabaseBinding
from domain.incident_credentials import candidate_secret_name
from ports.state import RecordConflict

FIELD = "security_credential_preparation"


class IncidentCredentialPreparation:
    def __init__(self, records, restriction, preparation, *, clock, revalidate):
        self.scope = IncidentDatabaseRestriction(records, restriction, clock=clock, revalidate=revalidate)
        self.writer, self.preparation = self.scope.writer, preparation
        self.clock = clock

    def status(self, principal, job_id):
        self.scope._authorized(principal)
        snapshot = self.writer.snapshot(principal, job_id)
        record = snapshot.record.get(FIELD)
        if record is None:
            return {"phase": "not_recorded"}
        if not preparation_record_is_valid(record):
            return {"phase": "needs_attention", "record_valid": False}
        return {**deepcopy(record), "record_valid": True}

    def inspect(
        self, principal, job_id, *, incident_id, expected_boundary, expected_operation_id, expected_revision
    ):
        started = self.clock()
        validate_release_request(
            incident_id, "credential-inspection", expected_revision, expected_boundary, started
        )
        if not isinstance(expected_operation_id, str) or not re.fullmatch(
            r"[a-f0-9]{32}", expected_operation_id
        ):
            raise ValueError("Exact credential preparation operation required")
        snapshot = self.scope._scope(principal, job_id, incident_id, expected_boundary)
        record = snapshot.record.get(FIELD)
        restriction = snapshot.record.get(RESTRICTION_FIELD)
        if (
            not preparation_record_is_valid(record)
            or not restriction_record_is_valid(restriction)
            or record["operation_id"] != expected_operation_id
            or record["incident_id"] != incident_id
            or record["boundary_id"] != expected_boundary
            or restriction["phase"] != "verified"
            or restriction["operation_id"] != record["restriction_operation_id"]
            or restriction["incident_id"] != incident_id
            or restriction["boundary_id"] != expected_boundary
            or restriction["binding"] != record["binding"]
            or record["binding"] != asdict(self.preparation.binding)
            or self.preparation.binding != self.scope.restriction.binding
            or record["resource_id"] != self.preparation.resource_id
            or record["candidate_access_principal"] != self.preparation.principal_arn
        ):
            raise ValueError("Current registered credential preparation intent required")
        if snapshot.revision != expected_revision:
            raise RecordConflict("Deployment changed since credential inspection request")

        def guard():
            current = self.scope._scope(principal, job_id, incident_id, expected_boundary)
            if (
                current.revision != snapshot.revision
                or current.record.get(FIELD) != record
                or current.record.get(RESTRICTION_FIELD) != restriction
            ):
                raise RecordConflict("Incident or credential preparation changed during inspection")

        try:
            guard()
            receipt = self.preparation.inspect(expected_operation_id, guard=guard)
            observed_at = self.clock()
            stamp = datetime.fromisoformat(observed_at)
            required = {
                "binding",
                "resource_id",
                "candidate_access_principal",
                "candidate_state",
                "candidate_secret_ref",
                "candidate_version_id",
                "login_enabled",
                "active_sessions",
                "read_only",
                "password_update_verified",
                "authentication_verified",
            }
            candidate_states = {
                "not_found",
                "registered_candidate",
                "scheduled_for_deletion",
                "version_mismatch",
                "policy_unverified",
            }
            if (
                not isinstance(receipt, dict)
                or set(receipt) != required
                or receipt["binding"] != record["binding"]
                or receipt["resource_id"] != record["resource_id"]
                or receipt["candidate_access_principal"] != record["candidate_access_principal"]
                or receipt["candidate_state"] not in candidate_states
                or type(receipt["login_enabled"]) is not bool
                or type(receipt["active_sessions"]) is not int
                or receipt["active_sessions"] < 0
                or receipt["read_only"] is not True
                or receipt["password_update_verified"] is not False
                or receipt["authentication_verified"] is not False
                or stamp.tzinfo is None
                or stamp < datetime.fromisoformat(started)
                or stamp < datetime.fromisoformat(record["requested_at"])
            ):
                raise ValueError("Exact read-only credential inspection receipt required")
            state = receipt["candidate_state"]
            arn, version = receipt["candidate_secret_ref"], receipt["candidate_version_id"]
            binding = self.preparation.binding
            prefix = f"arn:aws:secretsmanager:{binding.region}:{binding.account_id}:secret:{record['candidate_secret_name']}-"
            if state == "not_found":
                if arn is not None or version is not None:
                    raise ValueError("Absent candidate must not include a credential reference")
            elif (
                not isinstance(arn, str)
                or not re.fullmatch(re.escape(prefix) + r"[A-Za-z0-9]{6}", arn)
                or version != (expected_operation_id if state == "registered_candidate" else None)
            ):
                raise ValueError("Candidate reference or version differs from preparation intent")
            guard()
        except (PermissionError, RecordConflict):
            raise
        except Exception:  # noqa: BLE001 -- do not disclose secret metadata or SQL diagnostics
            raise OSError(
                "Credential inspection unavailable; no Secret, password or state change requested"
            ) from None
        observed = (
            "database_not_restricted"
            if receipt["login_enabled"] or receipt["active_sessions"]
            else "restricted_candidate_observed"
            if state == "registered_candidate"
            else "candidate_not_found"
            if state == "not_found"
            else "candidate_review_required"
        )
        return {
            "operation_id": expected_operation_id,
            "metadata_revision": snapshot.revision,
            "persisted_phase": record["phase"],
            "observed_state": observed,
            "observed_at": stamp.isoformat(),
            **deepcopy(receipt),
            "execution_exclusion_verified": False,
            "state_changed": False,
        }

    def prepare(
        self, principal, job_id, *, incident_id, expected_boundary, expected_operation_id, expected_revision
    ):
        now = self.clock()
        validate_release_request(
            incident_id, "credential-preparation", expected_revision, expected_boundary, now
        )
        if not isinstance(expected_operation_id, str) or not re.fullmatch(
            r"[a-f0-9]{32}", expected_operation_id
        ):
            raise ValueError("Exact restriction operation required")
        snapshot = self.scope._scope(principal, job_id, incident_id, expected_boundary)
        restriction = snapshot.record.get(RESTRICTION_FIELD)
        if (
            not restriction_record_is_valid(restriction)
            or restriction["phase"] != "verified"
            or restriction["operation_id"] != expected_operation_id
            or restriction["incident_id"] != incident_id
            or restriction["boundary_id"] != expected_boundary
            or restriction["binding"] != asdict(self.scope.restriction.binding)
            or self.preparation.binding != self.scope.restriction.binding
            or datetime.fromisoformat(now) < datetime.fromisoformat(restriction["verified_at"])
        ):
            raise ValueError("Verified current incident restriction required before credential preparation")
        previous = snapshot.record.get(FIELD)
        if previous is not None:
            if preparation_record_is_valid(previous) and all(
                previous.get(key) == value
                for key, value in {
                    "incident_id": incident_id,
                    "boundary_id": expected_boundary,
                    "restriction_operation_id": expected_operation_id,
                    "admitted_revision": expected_revision,
                    "requested_by": principal.user_id,
                    "binding": restriction["binding"],
                    "resource_id": self.preparation.resource_id,
                    "candidate_access_principal": self.preparation.principal_arn,
                }.items()
            ):
                return deepcopy(previous)
            raise ValueError("Existing credential preparation requires operator reconciliation")
        if snapshot.revision != expected_revision:
            raise RecordConflict("Deployment changed since credential preparation review")
        operation = uuid4().hex
        intent = {
            "schema_version": 1,
            "operation_id": operation,
            "restriction_operation_id": expected_operation_id,
            "incident_id": incident_id,
            "boundary_id": expected_boundary,
            "admitted_revision": expected_revision,
            "requested_by": principal.user_id,
            "requested_at": now,
            "binding": deepcopy(restriction["binding"]),
            "resource_id": self.preparation.resource_id,
            "candidate_access_principal": self.preparation.principal_arn,
            "candidate_secret_name": candidate_secret_name(self.preparation.resource_id, operation),
            "phase": "applying",
        }
        if not preparation_record_is_valid(intent):
            raise ValueError("Exact registered credential preparation intent required")
        try:
            self.writer.patch(
                principal, job_id, snapshot.revision, {FIELD: intent, "promotion_automation_consent": None}
            )
        except OSError:
            raise OSError(
                "Credential preparation admission uncertain; inspect intent before proceeding"
            ) from None

        def guard():
            current = self.scope._scope(principal, job_id, incident_id, expected_boundary)
            if current.record.get(FIELD) != intent or current.record.get(RESTRICTION_FIELD) != restriction:
                raise RecordConflict("Credential preparation execution ownership changed")
            return current

        try:
            guard()
            receipt = self.preparation.prepare(operation, guard=guard)
            prepared = {**intent, **receipt, "phase": "prepared_restricted", "prepared_at": self.clock()}
            if (
                set(receipt)
                != {
                    "binding",
                    "resource_id",
                    "candidate_secret_ref",
                    "candidate_version_id",
                    "password_update_acknowledged",
                    "login_enabled",
                    "active_sessions",
                    "authentication_verified",
                    "runtime_access_granted",
                    "candidate_access_principal",
                }
                or not preparation_record_is_valid(prepared)
                or receipt["binding"] != intent["binding"]
                or receipt["resource_id"] != intent["resource_id"]
                or receipt["candidate_access_principal"] != intent["candidate_access_principal"]
            ):
                raise ValueError("Exact restricted credential preparation receipt required")
            current = guard()
            self.writer.patch(principal, job_id, current.revision, {FIELD: prepared})
            return deepcopy(prepared)
        except Exception:  # noqa: BLE001 -- never leak SQL/Secret credentials or replay uncertain effects
            try:
                current = guard()
                self.writer.patch(
                    principal,
                    job_id,
                    current.revision,
                    {FIELD: {**intent, "phase": "needs_attention", "failure_code": "outcome_unconfirmed"}},
                )
            except Exception:  # noqa: BLE001,S110 -- retain the durable intent if state is unavailable
                pass
            raise OSError(
                "Credential preparation outcome needs inspection; access remains restricted"
            ) from None


def preparation_record_is_valid(value):
    base = {
        "schema_version",
        "operation_id",
        "restriction_operation_id",
        "incident_id",
        "boundary_id",
        "admitted_revision",
        "requested_by",
        "requested_at",
        "binding",
        "resource_id",
        "candidate_secret_name",
        "candidate_access_principal",
        "phase",
    }
    extra = {
        "applying": set(),
        "needs_attention": {"failure_code"},
        "prepared_restricted": {
            "candidate_secret_ref",
            "candidate_version_id",
            "prepared_at",
            "password_update_acknowledged",
            "login_enabled",
            "active_sessions",
            "authentication_verified",
            "runtime_access_granted",
        },
    }
    try:
        if (
            not isinstance(value, dict)
            or value.get("phase") not in extra
            or set(value) != base | extra[value["phase"]]
        ):
            return False
        if type(value["schema_version"]) is not int or value["schema_version"] != 1:
            return False
        validate_release_request(
            value["incident_id"],
            "credential-preparation",
            value["admitted_revision"],
            value["boundary_id"],
            value["requested_at"],
        )
        if not all(
            isinstance(value[key], str) and re.fullmatch(r"[a-f0-9]{32}", value[key])
            for key in ("operation_id", "restriction_operation_id")
        ):
            return False
        if not isinstance(value["requested_by"], str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", value["requested_by"]
        ):
            return False
        binding = DatabaseBinding(**value["binding"])
        if (
            binding.role not in {"shared_workload", "dedicated_workload"}
            or not isinstance(value["candidate_access_principal"], str)
            or not re.fullmatch(
                rf"arn:aws:iam::{binding.account_id}:(?:user|role)/[A-Za-z0-9+=,.@_/-]{{1,512}}",
                value["candidate_access_principal"],
            )
        ):
            return False
        name = candidate_secret_name(value["resource_id"], value["operation_id"])
        if value["candidate_secret_name"] != name:
            return False
        if value["phase"] == "needs_attention":
            return value["failure_code"] == "outcome_unconfirmed"
        if value["phase"] == "applying":
            return True
        prefix = f"arn:aws:secretsmanager:{binding.region}:{binding.account_id}:secret:{name}-"
        stamp = datetime.fromisoformat(value["prepared_at"])
        return (
            isinstance(value["candidate_secret_ref"], str)
            and re.fullmatch(re.escape(prefix) + r"[A-Za-z0-9]{6}", value["candidate_secret_ref"]) is not None
            and value["candidate_version_id"] == value["operation_id"]
            and value["password_update_acknowledged"] is True
            and value["login_enabled"] is False
            and type(value["active_sessions"]) is int
            and value["active_sessions"] == 0
            and value["authentication_verified"] is False
            and value["runtime_access_granted"] is False
            and stamp.tzinfo is not None
            and stamp >= datetime.fromisoformat(value["requested_at"])
        )
    except (ValueError, TypeError, KeyError):
        return False
