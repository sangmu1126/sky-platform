"""Registered read-only provider/resource identity evidence.

TCP reachability does not establish which provider resource a process reached.
This module binds opaque registered resource references to a read-only authority
and persists only exact-match results; raw provider diagnostics stay private.
"""

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta

from domain.environment_transition import _digest, _ref, _time
from domain.workload_inventory import RegisteredWorkloadInventory
from ports.workload_inventory import WorkloadInventoryUnavailable

PROVIDER_IDENTITY_CATEGORIES = ("external_api", "object_store", "queue")


@dataclass(frozen=True)
class RegisteredProviderResourceIdentity:
    logical_ref: str
    category: str
    location_ref: str
    provider_ref: str
    resource_kind: str
    resource_ref: str
    identity_sha256: str
    authority_ref: str

    def __post_init__(self):
        for value in (
            self.logical_ref,
            self.location_ref,
            self.provider_ref,
            self.resource_kind,
            self.resource_ref,
            self.authority_ref,
        ):
            _ref(value)
        if self.category not in PROVIDER_IDENTITY_CATEGORIES:
            raise ValueError("Provider identity category required")
        _digest(self.identity_sha256)


@dataclass(frozen=True)
class RegisteredProviderIdentityInventory:
    inventory: RegisteredWorkloadInventory
    endpoint: str
    authority_ref: str
    resources: tuple[RegisteredProviderResourceIdentity, ...]

    def __post_init__(self):
        if not isinstance(self.inventory, RegisteredWorkloadInventory):
            raise TypeError("Registered workload inventory required")
        if self.endpoint not in {"source", "target"}:
            raise ValueError("Registered provider identity endpoint required")
        _ref(self.authority_ref)
        if (
            not isinstance(self.resources, tuple)
            or len(self.resources) > 128
            or tuple(sorted(self.resources, key=lambda value: value.logical_ref)) != self.resources
            or len({value.logical_ref for value in self.resources}) != len(self.resources)
        ):
            raise ValueError("Canonical provider resource identities required")
        policies = {
            value.logical_ref: value
            for value in self.inventory.dependency_policies
            if value.category in PROVIDER_IDENTITY_CATEGORIES
        }
        if {value.logical_ref for value in self.resources} != set(policies):
            raise ValueError("Every provider dependency requires resource identity")
        for resource in self.resources:
            policy = policies[resource.logical_ref]
            location = policy.source_location_ref if self.endpoint == "source" else policy.target_location_ref
            if (resource.category, resource.location_ref) != (policy.category, location):
                raise ValueError("Provider resource identity differs from dependency policy")

    def document(self):
        value = {
            "schema_version": 1,
            "profile": "registered_provider_resource_identity_v1",
            "inventory_id": self.inventory.document()["inventory_id"],
            "endpoint": self.endpoint,
            "authority_ref": self.authority_ref,
            "resources": [asdict(value) for value in self.resources],
        }
        digest = hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        return {**value, "provider_identity_registration_id": "PIR-" + digest}


@dataclass(frozen=True)
class ObservedProviderResourceIdentity:
    logical_ref: str
    provider_ref: str
    resource_kind: str
    resource_ref: str
    identity_sha256: str
    authority_ref: str
    observed_at: datetime

    def __post_init__(self):
        for value in (
            self.logical_ref,
            self.provider_ref,
            self.resource_kind,
            self.resource_ref,
            self.authority_ref,
        ):
            _ref(value)
        _digest(self.identity_sha256)
        _time(self.observed_at)


@dataclass(frozen=True)
class ProviderIdentityEvidence:
    registration_id: str
    report_id: str
    observed_at: datetime
    expires_at: datetime

    def __post_init__(self):
        if not re.fullmatch(r"PIR-[a-f0-9]{64}", self.registration_id) or not re.fullmatch(
            r"WPI-[a-f0-9]{64}", self.report_id
        ):
            raise ValueError("Bound provider identity evidence required")
        _time(self.observed_at)
        _time(self.expires_at)
        if self.expires_at <= self.observed_at:
            raise ValueError("Positive provider identity evidence lifetime required")


def assess_provider_identity(registration, observations, *, now):
    if not isinstance(registration, RegisteredProviderIdentityInventory):
        raise TypeError("Registered provider identity inventory required")
    if not isinstance(observations, tuple) or len(observations) > 128:
        raise ValueError("Bounded provider identity observations required")
    _time(now)
    by_ref = {}
    duplicate_refs = set()
    for observation in observations:
        if not isinstance(observation, ObservedProviderResourceIdentity):
            raise TypeError("Typed provider identity observation required")
        if observation.logical_ref in by_ref:
            duplicate_refs.add(observation.logical_ref)
        by_ref[observation.logical_ref] = observation
    blockers = []
    resources = []
    for resource in registration.resources:
        observation = by_ref.get(resource.logical_ref)
        verified = bool(
            observation
            and resource.logical_ref not in duplicate_refs
            and observation.authority_ref == resource.authority_ref
            and (
                observation.provider_ref,
                observation.resource_kind,
                observation.resource_ref,
                observation.identity_sha256,
            )
            == (
                resource.provider_ref,
                resource.resource_kind,
                resource.resource_ref,
                resource.identity_sha256,
            )
            and 0 <= (now - observation.observed_at).total_seconds() <= 30
        )
        if not verified:
            blockers.append("provider_identity_unverified:" + resource.logical_ref)
        resources.append(
            {
                **asdict(resource),
                "identity_verified": verified,
            }
        )
    if set(by_ref) - {value.logical_ref for value in registration.resources}:
        blockers.append("unregistered_provider_identity_observed")
    document = registration.document()
    value = {
        "schema_version": 1,
        "profile": document["profile"],
        "provider_identity_registration_id": document["provider_identity_registration_id"],
        "inventory_id": document["inventory_id"],
        "endpoint": registration.endpoint,
        "authority_ref": registration.authority_ref,
        "evaluated_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=registration.inventory.max_age_seconds)).isoformat(),
        "status": "verified" if not blockers else "blocked",
        "blockers": sorted(set(blockers)),
        "resources": resources,
        "execution_authorized": False,
    }
    digest = hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    return {**value, "report_id": "WPI-" + digest}


def validate_provider_identity_report(registration, document):
    try:
        if not isinstance(registration, RegisteredProviderIdentityInventory):
            raise TypeError("Registered provider identity inventory required")
        raw = json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False)
        fields = {
            "schema_version",
            "profile",
            "provider_identity_registration_id",
            "inventory_id",
            "endpoint",
            "authority_ref",
            "evaluated_at",
            "expires_at",
            "status",
            "blockers",
            "resources",
            "execution_authorized",
            "report_id",
        }
        registered = registration.document()
        if (
            not isinstance(document, dict)
            or set(document) != fields
            or len(raw.encode()) > 256 * 1024
            or document["schema_version"] != 1
            or document["profile"] != registered["profile"]
            or document["provider_identity_registration_id"]
            != registered["provider_identity_registration_id"]
            or document["inventory_id"] != registered["inventory_id"]
            or document["endpoint"] != registration.endpoint
            or document["authority_ref"] != registration.authority_ref
            or document["execution_authorized"] is not False
            or document["status"] not in {"blocked", "verified"}
        ):
            raise ValueError("Provider identity report differs from registration")
        evaluated = datetime.fromisoformat(document["evaluated_at"])
        expires = datetime.fromisoformat(document["expires_at"])
        _time(evaluated)
        _time(expires)
        if expires != evaluated + timedelta(seconds=registration.inventory.max_age_seconds):
            raise ValueError("Provider identity evidence lifetime changed")
        blockers = document["blockers"]
        if (
            not isinstance(blockers, list)
            or blockers != sorted(set(blockers))
            or any(not isinstance(value, str) or not 1 <= len(value) <= 256 for value in blockers)
            or (document["status"] == "verified") != (not blockers)
        ):
            raise ValueError("Invalid provider identity blockers")
        resources = document["resources"]
        expected = [
            {**asdict(value), "identity_verified": document["status"] == "verified"}
            for value in registration.resources
        ]
        if not isinstance(resources, list) or len(resources) != len(expected):
            raise ValueError("Canonical provider identity resources required")
        for actual, registered_resource in zip(resources, registration.resources):
            expected_fields = {**asdict(registered_resource), "identity_verified": False}
            if (
                not isinstance(actual, dict)
                or set(actual) != set(expected_fields)
                or {key: value for key, value in actual.items() if key != "identity_verified"}
                != asdict(registered_resource)
                or type(actual["identity_verified"]) is not bool
            ):
                raise ValueError("Invalid provider identity resource evidence")
        if document["status"] == "verified" and resources != expected:
            raise ValueError("Verified provider identity report contains drift")
        unsigned = {key: value for key, value in document.items() if key != "report_id"}
        digest = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        if document["report_id"] != "WPI-" + digest:
            raise ValueError("Provider identity report identity changed")
        return json.loads(raw)
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        raise ValueError("Invalid provider identity report") from None


class ProviderIdentityEvidenceReader:
    def __init__(self, registration, inspector, publisher, *, clock):
        if not isinstance(registration, RegisteredProviderIdentityInventory):
            raise TypeError("Registered provider identity inventory required")
        if not all(
            callable(value)
            for value in (getattr(inspector, "inspect", None), getattr(publisher, "publish", None), clock)
        ):
            raise TypeError("Provider identity inspector, publisher and clock required")
        self.registration = registration
        self.inspector = inspector
        self.publisher = publisher
        self.clock = clock

    def collect(self, inventory, endpoint):
        if inventory != self.registration.inventory or endpoint != self.registration.endpoint:
            raise ValueError("Provider identity registration changed")
        try:
            observations = []
            for resource in self.registration.resources:
                try:
                    observation = self.inspector.inspect(resource)
                except Exception:  # noqa: BLE001 -- provider diagnostics remain private
                    observation = None
                if isinstance(observation, ObservedProviderResourceIdentity):
                    observations.append(observation)
            now = self.clock()
            report = assess_provider_identity(self.registration, tuple(observations), now=now)
            report_id = self.publisher.publish(json.loads(json.dumps(report)))
            if report_id != report["report_id"] or report["status"] != "verified":
                raise ValueError("Provider resource identity was not durably verified")
            return ProviderIdentityEvidence(
                self.registration.document()["provider_identity_registration_id"],
                report_id,
                now,
                now + timedelta(seconds=inventory.max_age_seconds),
            )
        except Exception:  # noqa: BLE001 -- raw provider identity details remain private
            raise WorkloadInventoryUnavailable("Registered provider identity unavailable") from None


class ProviderIdentityInspectorRouter:
    """Dispatch one registration across separately pinned provider authorities."""

    def __init__(self, bindings):
        if (
            not isinstance(bindings, tuple)
            or not 1 <= len(bindings) <= 16
            or tuple(sorted(bindings, key=lambda value: value[0])) != bindings
            or len({value[0] for value in bindings}) != len(bindings)
        ):
            raise ValueError("Canonical provider identity inspector bindings required")
        for provider_ref, inspector in bindings:
            _ref(provider_ref)
            if not callable(getattr(inspector, "inspect", None)):
                raise TypeError("Provider identity inspector binding required")
        self.inspectors = dict(bindings)

    def inspect(self, resource):
        if not isinstance(resource, RegisteredProviderResourceIdentity):
            raise TypeError("Registered provider resource identity required")
        inspector = self.inspectors.get(resource.provider_ref)
        if inspector is None:
            raise ValueError("Registered provider identity inspector unavailable")
        return inspector.inspect(resource)
