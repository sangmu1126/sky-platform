"""Repeated incidents preserve every recorded denied role incarnation."""

from copy import deepcopy
from unittest.mock import Mock

import pytest

from application.incident_secret_access import FIELD, access_context
from domain.incident_secret_access import deny_runtime_secret_policy
from tests.unit.test_incident_secret_access import fixture

pytest_plugins = ["tests.unit.test_operating_review", "tests.unit.test_security_hold_cli"]


def archive_and_replace_roles(f, *, recovery_id="1" * 32):
    fence = f.service.fence(f.actor, f.records.job["id"], **f.args)
    old_context = deepcopy(f.context)
    controls = {k: deepcopy(v) for k, v in f.records.job.items() if k.startswith("security_")}
    controls["security_recovery"] = {
        "id": recovery_id,
        "phase": "verified",
        "external_pending": False,
        "incident_id": fence["incident_id"],
        "boundary_id": fence["boundary_id"],
    }
    audit = {
        "id": recovery_id,
        "incident_id": fence["incident_id"],
        "prior_boundary": fence["boundary_id"],
        "controls": controls,
        "prior_result": deepcopy(f.records.job["result"]),
    }
    f.records.job.setdefault("security_incident_history", []).append(audit)
    f.records.job.pop(FIELD)
    for role in f.roles.values():
        role["RoleId"] = "AROA" + chr(ord(role["RoleId"][-1]) + 2) * 17
    f.context = access_context(f.records.job, f.registration)
    f.args["expected_revision"] = f.records.revision
    return fence, old_context


def test_second_and_third_incident_keep_all_prior_role_denials(operating_review_setup):
    f = fixture(operating_review_setup)
    first, _ = archive_and_replace_roles(f)
    assert f.context["prior_role_ids"] == sorted(first["target"]["roles"].values())
    second, _ = archive_and_replace_roles(f, recovery_id="2" * 32)
    expected_prior = sorted(set(first["target"]["roles"].values()) | set(second["target"]["roles"].values()))
    assert f.context["prior_role_ids"] == expected_prior
    target = f.adapter.preflight(f.context, guard=lambda: None)
    f.adapter.fence(f.context, target, guard=lambda: None)
    assert f.policies[f.registration.secret_arn] == deny_runtime_secret_policy(
        target, prior_role_ids=expected_prior
    )
    assert f.adapter.inspect(f.context, target, guard=lambda: None)["policy_state"] == "runtime_roles_denied"
    # Read-only inspection must also reject loss of an OLD deny, not only current roles.
    f.policies[f.registration.secret_arn] = deny_runtime_secret_policy(target)
    assert f.adapter.inspect(f.context, target, guard=lambda: None)["policy_state"] == "review_required"


@pytest.mark.parametrize(
    "change", ["missing", "extra-role", "extra-statement", "allow", "changed-after-preflight"]
)
def test_unreviewed_or_incomplete_old_policy_never_gets_replaced(operating_review_setup, change):
    f = fixture(operating_review_setup)
    archive_and_replace_roles(f)
    target = f.adapter.preflight(f.context, guard=lambda: None)
    f.clients["secretsmanager"].put_resource_policy.reset_mock()
    if change == "missing":
        f.policies[f.registration.secret_arn] = None
    elif change == "extra-statement":
        f.policies[f.registration.secret_arn]["Statement"].append({"Effect": "Deny"})
    elif change == "allow":
        f.policies[f.registration.secret_arn]["Statement"][0]["Effect"] = "Allow"
    else:
        values = f.policies[f.registration.secret_arn]["Statement"][0]["Condition"]["StringLike"][
            "aws:userid"
        ]
        values.append("AROA" + "Z" * 17 + ":*")
    with pytest.raises(ValueError):
        if change != "changed-after-preflight":
            f.adapter.preflight(f.context, guard=lambda: None)
        else:
            f.adapter.fence(f.context, target, guard=lambda: None)
    f.clients["secretsmanager"].put_resource_policy.assert_not_called()


@pytest.mark.parametrize(
    "change",
    [
        "bad-digest",
        "other-secret",
        "incomplete-fence",
        "missing-recovery",
        "pending-recovery",
        "wrong-incident",
        "duplicate",
        "oversize",
        "not-list",
    ],
)
def test_invalid_history_fails_before_native_requests(operating_review_setup, change):
    f = fixture(operating_review_setup)
    archive_and_replace_roles(f)
    history = f.records.job["security_incident_history"]
    audit = history[0]
    if change == "bad-digest":
        audit["controls"][FIELD]["context_digest"] = "a" * 64
    elif change == "other-secret":
        audit["prior_result"]["database"]["secret_arn"] += "foreign"
    elif change == "incomplete-fence":
        audit["controls"][FIELD].pop("recorded_at")
    elif change == "missing-recovery":
        audit["controls"].pop("security_recovery")
    elif change == "pending-recovery":
        audit["controls"]["security_recovery"]["external_pending"] = True
    elif change == "wrong-incident":
        audit["incident_id"] = "9" * 32
    elif change == "duplicate":
        history.append(deepcopy(audit))
    elif change == "oversize":
        f.records.job["security_incident_history"] = history * 11
    else:
        f.records.job["security_incident_history"] = {}
    f.service.adapter = Mock()
    with pytest.raises((ValueError, TypeError, KeyError)):
        f.service.fence(f.actor, f.records.job["id"], **f.args)
    assert not f.service.adapter.method_calls


def test_history_mutation_during_native_preflight_does_not_issue_policy_write(operating_review_setup):
    f = fixture(operating_review_setup)
    archive_and_replace_roles(f)
    method = f.clients["secretsmanager"].get_resource_policy
    observe = method.side_effect

    def mutate(**kw):
        result = observe(**kw)
        f.records.job["security_incident_history"][0]["controls"][FIELD]["context_digest"] = "f" * 64
        return result

    method.side_effect = mutate
    f.clients["secretsmanager"].put_resource_policy.reset_mock()
    with pytest.raises(OSError):
        f.service.fence(f.actor, f.records.job["id"], **f.args)
    f.clients["secretsmanager"].put_resource_policy.assert_not_called()


@pytest.mark.parametrize(
    "values",
    [None, "AROA" + "A" * 17, ["*"], ["AROA" + "A" * 17] * 2, ["AROA" + "B" * 17, "AROA" + "A" * 17]],
)
def test_malformed_historical_identity_set_never_reaches_aws(operating_review_setup, values):
    f = fixture(operating_review_setup)
    f.context["prior_role_ids"] = values
    for client in f.clients.values():
        client.reset_mock()
    with pytest.raises(ValueError):
        f.adapter.preflight(f.context, guard=lambda: None)
    assert all(not client.method_calls for client in f.clients.values())


def test_postgresql_source_recovery_archive_preserves_old_role_denials(operating_review_setup):
    from ports.remote_builds import digest

    f = fixture(operating_review_setup)
    first, _ = archive_and_replace_roles(f)
    audit = f.records.job["security_incident_history"][0]
    old = audit["controls"].pop("security_recovery")
    plan = {"image": "new-verified-image"}
    audit["kind"] = "source_recovery"
    audit["controls"]["security_source_recovery"] = {
        "recovery_id": old["id"],
        "phase": "verified",
        "scope": "new_source_recovery_only",
        "profile": "postgresql",
        "job_id": f.records.job["id"],
        "organization_id": f.records.job["organization_id"],
        "incident_id": audit["incident_id"],
        "boundary_id": audit["prior_boundary"],
        "plan": plan,
        "plan_digest": digest(plan),
        "result": {"image": plan["image"], "verification": {"database_authentication": "verified"}},
    }
    current = access_context(f.records.job, f.registration)
    assert current["prior_role_ids"] == sorted(first["target"]["roles"].values())
    audit["controls"]["security_source_recovery"]["profile"] = "stateless-http"
    with pytest.raises(ValueError):
        access_context(f.records.job, f.registration)
