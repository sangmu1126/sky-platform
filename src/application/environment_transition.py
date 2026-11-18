"""Worker/operator-only ID-based collection. No provider-bearing HTTP handler.

The principal comes from a trusted current authentication boundary. Queue
consumers must reload it, never deserialize a queued claim as authority. The
membership callback and authorizer recheck membership/ownership before and after
collection. The existing app-owner authorizer alone does not reload membership.
"""

from dataclasses import dataclass
from types import MappingProxyType

from domain.access import Principal, Role
from domain.environment_transition import (
    PreservationObservation,
    PreservationRequirement,
    TransitionScope,
    _ref,
    validate_preservation_requirements,
)
from engine.environment_transition import assess_environment_transition
from ports.environment_transition import PreservationCollectionUnavailable


@dataclass(frozen=True)
class RegisteredPreservationCollector:
    verifier_ref: str
    requirements: tuple[PreservationRequirement, ...]
    collector: object

    def __post_init__(self):
        _ref(self.verifier_ref)
        if (
            not isinstance(self.requirements, tuple)
            or not self.requirements
            or not all(isinstance(item, PreservationRequirement) for item in self.requirements)
            or len({item.capability for item in self.requirements}) != len(self.requirements)
            or not callable(getattr(self.collector, "collect", None))
        ):
            raise ValueError("Explicit registered collector and unique criteria required")


@dataclass(frozen=True)
class RegisteredEnvironmentTransition:
    registration_id: str
    scope: TransitionScope
    requirements: tuple[PreservationRequirement, ...]
    collectors: tuple[RegisteredPreservationCollector, ...]

    def __post_init__(self):
        _ref(self.registration_id)
        if not isinstance(self.scope, TransitionScope):
            raise TypeError("Typed registered transition scope required")
        validate_preservation_requirements(self.requirements)
        if (
            not isinstance(self.collectors, tuple)
            or len(self.collectors) > 64
            or not all(isinstance(item, RegisteredPreservationCollector) for item in self.collectors)
        ):
            raise ValueError("Bounded immutable registered collectors required")
        assigned = set()
        verifiers = set()
        for binding in self.collectors:
            if binding.verifier_ref in verifiers:
                raise ValueError("Duplicate registered verifier")
            verifiers.add(binding.verifier_ref)
            for requirement in binding.requirements:
                if requirement not in self.requirements or requirement.capability in assigned:
                    raise ValueError("Unregistered or ambiguously assigned preservation criterion")
                assigned.add(requirement.capability)


class OperatorTransitionRegistry:
    """Immutable process configuration, not a persistent resource registry.

    No requests can add entries. Production must populate/reload registrations
    from authoritative revisions and pin actual provider/VM resources. Current
    resource ownership still belongs to collectors, not this configuration.
    """

    def __init__(self, registrations: tuple[RegisteredEnvironmentTransition, ...]):
        if not isinstance(registrations, tuple) or not all(
            isinstance(item, RegisteredEnvironmentTransition) for item in registrations
        ):
            raise ValueError("Typed operator transition registrations required")
        entries = {(item.scope.organization_id, item.registration_id): item for item in registrations}
        if len(entries) != len(registrations):
            raise ValueError("Duplicate registered transition")
        self._entries = MappingProxyType(entries)

    def resolve(self, organization_id: str, registration_id: str) -> RegisteredEnvironmentTransition:
        try:
            return self._entries[(organization_id, registration_id)]
        except KeyError:
            raise FileNotFoundError("Transition not found") from None


class EnvironmentTransitionReviewService:
    def __init__(
        self, registry, authorizer, *, current_principal, clock, max_age_seconds=300, review_store=None
    ):
        if type(max_age_seconds) is not int or not 1 <= max_age_seconds <= 300:
            raise ValueError("Bounded transition observation age required")
        self.registry, self.authorizer = registry, authorizer
        if not callable(current_principal):
            raise TypeError("Current membership resolver required")
        self.current_principal = current_principal
        self.clock, self.max_age = clock, max_age_seconds
        self.review_store = review_store

    def review_and_record(self, principal: Principal, registration_id: str):
        """Collect by registered ID and persist internally, never accept client evidence."""
        if not isinstance(principal, Principal):
            raise PermissionError("Authenticated principal required")
        _ref(registration_id)
        if self.review_store is None:
            raise ValueError("Durable environment review store is not configured")
        registration = self.registry.resolve(principal.organization_id, registration_id)
        document = self.review(principal, registration_id)
        if self.current_principal(principal) != principal:
            raise PermissionError("Transition membership changed before recording")
        if self.registry.resolve(principal.organization_id, registration_id) is not registration:
            raise ValueError("Transition registration changed before recording")
        self.authorizer.authorize(principal, registration.scope.application_id)
        stored = self.review_store.record(principal, registration_id, document)
        if self.current_principal(principal) != principal:
            raise PermissionError("Transition membership changed after recording")
        if self.registry.resolve(principal.organization_id, registration_id) is not registration:
            raise ValueError("Transition registration changed after recording")
        return stored, document

    def review(self, principal: Principal, registration_id: str) -> dict:
        if not isinstance(principal, Principal):
            raise PermissionError("Authenticated principal required")
        _ref(registration_id)
        if self.current_principal(principal) != principal:
            raise PermissionError("Transition membership changed")
        registration = self.registry.resolve(principal.organization_id, registration_id)
        if (
            not isinstance(registration, RegisteredEnvironmentTransition)
            or registration.scope.organization_id != principal.organization_id
            or registration.registration_id != registration_id
        ):
            raise FileNotFoundError("Transition not found")
        if principal.role not in {Role.ADMIN, Role.DEPLOYER}:
            raise PermissionError("Transition review permission required")

        def recheck():
            if self.current_principal(principal) != principal:
                raise PermissionError("Transition membership changed")
            self.authorizer.authorize(principal, registration.scope.application_id)
            if self.registry.resolve(principal.organization_id, registration_id) is not registration:
                raise ValueError("Transition registration changed during collection")

        recheck()
        observations = []
        for binding in registration.collectors:
            recheck()
            try:
                results = binding.collector.collect(registration.scope, binding.requirements)
            except PreservationCollectionUnavailable:
                # No provider diagnostics/credentials or optimistic placeholder.
                results = ()
            if not isinstance(results, tuple) or len(results) > 2 * len(binding.requirements):
                raise ValueError("Invalid registered collection result")
            if any(
                not isinstance(item, PreservationObservation)
                or item.verifier_ref != binding.verifier_ref
                or item.requirement not in binding.requirements
                or item.origin != "collector"
                for item in results
            ):
                raise ValueError("Collection exceeded registered evidence authority")
            observations.extend(results)
        recheck()
        return assess_environment_transition(
            registration.scope,
            registration.requirements,
            tuple(observations),
            now=self.clock(),
            max_age_seconds=self.max_age,
        )
