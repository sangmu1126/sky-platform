"""Environment runtime secrets remain version-pinned, scoped, and guard-bound."""

from contextlib import contextmanager
from dataclasses import replace
from unittest.mock import Mock

import pytest

from adapters.database.environment_control import EnvironmentApplicationControl
from adapters.database.environment_execution_runtime import (
    RegisteredEnvironmentRuntimeSecret,
    RegisteredEnvironmentTransferRuntime,
    RegisteredEnvironmentTransferRuntimeRegistration,
)
from adapters.database.environment_fence import PostgresEnvironmentWriteFence
from adapters.database.environment_traffic import EnvironmentBlueGreenTraffic
from application.environment_cutover import EnvironmentDatabaseCutover
from application.environment_execution_effect import RegisteredEnvironmentTransferEffect
from tests.unit.test_database_transfer import adapter
from tests.unit.test_environment_admission import registered
from tests.unit.test_environment_router import fixture as router_fixture

PURPOSES = (
    "router_transport",
    "entrypoint_probe",
    "source_control",
    "source_database",
    "target_control",
    "target_database",
)


def registration(execution):
    return RegisteredEnvironmentTransferRuntimeRegistration(
        execution.revision,
        "ESR-" + "a" * 64,
        "RTC-" + "b" * 64,
        tuple(
            RegisteredEnvironmentRuntimeSecret(purpose, "secret-" + purpose, "version-" + purpose)
            for purpose in PURPOSES
        ),
    )


class Resolver:
    def __init__(self, values=None, *, fail_close=False):
        self.values = values or {purpose: "material-" + purpose for purpose in PURPOSES}
        self.events = []
        self.fail_close = fail_close

    @contextmanager
    def open(self, reference, version, *, execution, purpose, guard):
        self.events.append(("open", purpose, reference, version, execution.revision, guard))
        try:
            yield self.values.get(purpose)
        finally:
            self.events.append(("close", purpose))
            if self.fail_close and purpose == "router_transport":
                raise RuntimeError("private cleanup detail")


def composer_fixture(tmp_path, execution):
    _transfer, transport, _endpoints, _verifiers, _connects = adapter(tmp_path)
    router, _state, _container = router_fixture()

    def compose(selected, materials, *, guard, journal):
        assert selected == execution
        assert set(materials) == set(PURPOSES)
        router.guard = guard
        source = EnvironmentApplicationControl(
            selected.job.transfer,
            "https://source.test/control",
            materials["source_control"],
            controller_id="source-controller",
            guard=guard,
            transport=Mock(),
        )
        target = EnvironmentApplicationControl(
            selected.job.transfer,
            "https://target.test/control",
            materials["target_control"],
            controller_id="target-controller",
            guard=guard,
            transport=Mock(),
        )
        traffic = EnvironmentBlueGreenTraffic(selected.job.transfer, source, target, router, guard=guard)
        source_fence = PostgresEnvironmentWriteFence(
            transport, "source", "sky_transfer_" + "a" * 16, "sky-transfer-v1:" + "c" * 64
        )
        target_fence = PostgresEnvironmentWriteFence(
            transport, "target", "sky_transfer_" + "b" * 16, "sky-transfer-v1:" + "d" * 64
        )
        flow = EnvironmentDatabaseCutover(
            selected.job.transfer,
            transport,
            source_fence,
            target_fence,
            traffic,
            guard=guard,
            journal=journal,
        )
        return transport, flow

    return compose


def runtime_fixture(tmp_path):
    execution = registered()
    resolver = Resolver()
    runtime = RegisteredEnvironmentTransferRuntime(
        execution, registration(execution), resolver, composer_fixture(tmp_path, execution)
    )
    return execution, resolver, runtime


def test_runtime_reference_binds_execution_resolver_composition_and_secret_versions(tmp_path):
    execution, _resolver, runtime = runtime_fixture(tmp_path)
    document = runtime.registration.document()
    assert runtime.reference == document["runtime_ref"]
    assert runtime.reference.startswith("ETR-")
    assert "material" not in str(document)

    changed = replace(
        runtime.registration,
        secrets=tuple(
            replace(value, version_ref="new-version") if value.purpose == "target_database" else value
            for value in runtime.registration.secrets
        ),
    )
    assert changed.document()["runtime_ref"] != runtime.reference
    assert RegisteredEnvironmentTransferEffect(execution, runtime.reference, runtime).reference.startswith(
        "EEF-"
    )


def test_runtime_opens_exact_versions_and_closes_them_in_reverse_order(tmp_path):
    execution, resolver, runtime = runtime_fixture(tmp_path)
    guard, journal = Mock(), Mock()
    with runtime(execution, guard=guard, journal=journal) as (transport, flow):
        assert flow.transfer == transport.transfer == execution.job.transfer
        assert flow._external_guard is guard and flow.journal is journal
        assert [value[1] for value in resolver.events if value[0] == "open"] == list(PURPOSES)
    assert [value[1] for value in resolver.events if value[0] == "close"] == list(reversed(PURPOSES))
    assert guard.call_count == 13


def test_resolution_or_composition_drift_is_sanitized_and_open_secrets_close(tmp_path):
    execution, resolver, runtime = runtime_fixture(tmp_path)
    resolver.values["source_database"] = None
    with (
        pytest.raises(OSError, match="runtime unavailable") as error,
        runtime(execution, guard=Mock(), journal=Mock()),
    ):
        pass
    assert "source_database" not in str(error.value)
    assert [value[1] for value in resolver.events if value[0] == "close"] == [
        "source_database",
        "source_control",
        "entrypoint_probe",
        "router_transport",
    ]

    resolver = Resolver()
    runtime = RegisteredEnvironmentTransferRuntime(
        execution,
        registration(execution),
        resolver,
        lambda *_args, **_kwargs: (Mock(), Mock()),
    )
    with (
        pytest.raises(OSError, match="runtime unavailable"),
        runtime(execution, guard=Mock(), journal=Mock()),
    ):
        pass
    assert len([value for value in resolver.events if value[0] == "close"]) == 6


def test_effect_failure_propagates_after_runtime_validation_and_still_closes_secrets(tmp_path):
    execution, resolver, runtime = runtime_fixture(tmp_path)

    class EffectFailure(Exception):
        pass

    with pytest.raises(EffectFailure), runtime(execution, guard=Mock(), journal=Mock()):
        raise EffectFailure("external effect outcome")
    assert len([value for value in resolver.events if value[0] == "close"]) == 6


def test_secret_cleanup_never_replaces_an_uncertain_effect_outcome(tmp_path):
    execution = registered()
    resolver = Resolver(fail_close=True)
    runtime = RegisteredEnvironmentTransferRuntime(
        execution, registration(execution), resolver, composer_fixture(tmp_path, execution)
    )

    class EffectFailure(Exception):
        pass

    with pytest.raises(EffectFailure) as error, runtime(execution, guard=Mock(), journal=Mock()):
        raise EffectFailure("external effect outcome")
    assert "external effect outcome" in str(error.value)
    assert error.value.__notes__ == ["Registered environment runtime secret cleanup failed"]

    resolver = Resolver(fail_close=True)
    runtime = RegisteredEnvironmentTransferRuntime(
        execution, registration(execution), resolver, composer_fixture(tmp_path, execution)
    )
    with (
        pytest.raises(OSError, match="secret cleanup failed") as cleanup,
        runtime(execution, guard=Mock(), journal=Mock()),
    ):
        pass
    assert "private cleanup detail" not in str(cleanup.value)


@pytest.mark.parametrize("change", ["order", "purpose", "duplicate", "execution", "resolver"])
def test_runtime_registration_rejects_ambiguous_or_changed_authority(tmp_path, change):
    execution, resolver, runtime = runtime_fixture(tmp_path)
    value = runtime.registration
    with pytest.raises(ValueError):
        if change == "order":
            value = replace(value, secrets=tuple(reversed(value.secrets)))
        elif change == "purpose":
            value = replace(
                value,
                secrets=(replace(value.secrets[0], purpose="unknown"), *value.secrets[1:]),
            )
        elif change == "duplicate":
            value = replace(
                value,
                secrets=(
                    value.secrets[0],
                    replace(value.secrets[1], secret_ref=value.secrets[0].secret_ref),
                    *value.secrets[2:],
                ),
            )
        elif change == "execution":
            value = replace(value, execution_revision="f" * 64)
        else:
            value = replace(value, secret_resolver_ref="latest")
        RegisteredEnvironmentTransferRuntime(execution, value, resolver, runtime.composer)
