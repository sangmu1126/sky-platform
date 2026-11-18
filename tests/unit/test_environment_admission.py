"""Execution admission policy binds exact reviewed evidence without effects."""

from dataclasses import replace
from datetime import timedelta

import pytest

from application.environment_admission import (
    RegisteredEnvironmentExecution,
    environment_execution_command,
    require_current_execution_gate,
)
from application.environment_gate_review import advance_preservation_gate
from application.environment_jobs import RegisteredEnvironmentJob
from domain.access import LoginSource, Principal, ResourceOwner, Role
from tests.unit.test_database_transfer import transfer
from tests.unit.test_environment_gate_review import case, observations
from tests.unit.test_environment_transition import NOW


def registered():
    policy, _ = case()
    job = RegisteredEnvironmentJob(
        "game",
        ResourceOwner("org", "operator"),
        transfer(),
        NOW + timedelta(hours=1),
        "http://127.0.0.1:8780/",
        "b" * 64,
    )
    return RegisteredEnvironmentExecution(job, policy, "registered-route")


def gate(execution, through="G7"):
    previous = None
    for index in range(int(through[1]) + 1):
        name = "G" + str(index)
        previous = advance_preservation_gate(
            execution.policy,
            previous,
            name,
            observations(execution.policy, NOW, through=name),
            now=NOW,
        )
    return previous


def actor():
    return Principal("operator", "org", Role.DEPLOYER, LoginSource.PRIVATE_OPERATOR)


def test_execution_revision_binds_runtime_transfer_and_preservation_policy():
    value = registered()
    changed_job = replace(value.job, input_sha256="c" * 64)
    changed_policy = replace(
        value.policy,
        scope=replace(value.policy.scope, target_configuration_revision="e" * 64),
    )
    assert (
        len(
            {
                value.revision,
                replace(value, job=changed_job).revision,
                replace(value, policy=changed_policy).revision,
            }
        )
        == 3
    )


@pytest.mark.parametrize("change", ["organization", "application", "source_revision", "review"])
def test_execution_cannot_bind_a_foreign_or_changed_transfer(change):
    value = registered()
    if change == "review":
        with pytest.raises(ValueError, match="scope differs"):
            replace(value, review_registration_id="other-route")
        return
    field, altered = {
        "organization": ("organization_id", "other"),
        "application": ("application_id", "other"),
        "source_revision": ("source_revision", "e" * 64),
    }[change]
    policy = replace(value.policy, scope=replace(value.policy.scope, **{field: altered}))
    with pytest.raises(ValueError, match="scope differs"):
        replace(value, policy=policy)


def test_only_exact_fresh_g7_record_can_cross_the_pre_effect_boundary():
    execution = registered()
    record = gate(execution)
    assert (
        require_current_execution_gate(execution, record, now=NOW, expected_record_id=record["record_id"])
        == record
    )
    with pytest.raises(ValueError, match="Exact pre-effect"):
        require_current_execution_gate(
            execution,
            record,
            now=NOW,
            expected_record_id="EGR-" + "f" * 64,
        )
    with pytest.raises(ValueError, match="expired"):
        require_current_execution_gate(
            execution,
            record,
            now=NOW + timedelta(seconds=301),
            expected_record_id=record["record_id"],
        )
    earlier = gate(execution, "G6")
    with pytest.raises(ValueError, match="Exact pre-effect"):
        require_current_execution_gate(execution, earlier, now=NOW, expected_record_id=earlier["record_id"])


def test_admitted_command_contains_only_opaque_review_refs_and_explicit_consent():
    execution = registered()
    record = gate(execution)
    command = environment_execution_command(
        actor(),
        execution,
        review_id="review-id",
        report_id="ENV-" + "a" * 64,
        gate_record_id=record["record_id"],
        request_key="request-one",
        confirm_write_pause=True,
        confirm_websocket_reconnect=True,
    )
    assert command["registration_revision"] == execution.revision
    assert command["action"] == "transfer"
    assert command["write_pause_consent"] and command["websocket_reconnect_consent"]
    assert not any(key in command for key in ("dsn", "password", "hostname", "command"))
    with pytest.raises(ValueError, match="Explicit write pause"):
        environment_execution_command(
            actor(),
            execution,
            review_id="review-id",
            report_id="ENV-" + "a" * 64,
            gate_record_id=record["record_id"],
            request_key="request-one",
            confirm_write_pause=False,
            confirm_websocket_reconnect=True,
        )
