from unittest.mock import Mock

import pytest

from application.environment_agent_tools import InvestigationReceipt, InvestigationTools
from domain.access import LoginSource, Principal, Role
from tests.unit.test_environment_transition import setup


def case(**kwargs):
    scope, _, _ = setup()
    actor = Principal("alice", "org", Role.DEPLOYER, LoginSource.CORPORATE_SSO)
    handler = Mock(return_value=InvestigationReceipt("metadata", ("http_container", "target_unverified")))
    membership = Mock(side_effect=lambda value: value)
    authorizer = Mock()
    artifact = Mock(return_value=True)
    tools = InvestigationTools(
        actor,
        scope,
        {"get_system_inventory": handler},
        {
            "environment": ("aws-prod", "vm-target"),
            "criterion": ("runtime-policy",),
            "evidence": ("evidence-" + "a" * 64,),
            "change": ("approved-change",),
            "proposal": ("proposal-" + "b" * 64,),
        },
        current_principal=membership,
        authorizer=authorizer,
        verify_artifact=artifact,
        **kwargs,
    )
    return tools, handler, membership, authorizer, artifact


def test_registered_context_checks_membership_owner_and_keeps_unknowns():
    tools, handler, membership, authorizer, _ = case()
    result = tools.invoke("get_system_inventory", {})
    assert result.fact_codes == ("http_container", "target_unverified")
    assert membership.call_count == 3 and authorizer.authorize.call_count == 3
    assert handler.call_args.args[:2] == (tools.principal, tools.scope)


@pytest.mark.parametrize(
    "name,args",
    [
        ("shell", {"command": "aws sts get-caller-identity"}),
        ("get_system_inventory", {"organization_id": "other"}),
        ("get_system_inventory", {"url": "http://169.254.169.254"}),
        ("get_environment_capabilities", {"environment_ref": "unregistered"}),
        ("read_evidence", {"evidence_ref": "secret-ref"}),
        (
            "propose_change",
            {
                "source_revision": "b" * 64,
                "evidence_refs": ["evidence-" + "a" * 64],
                "change_ref": "approved-change",
            },
        ),
        (
            "propose_change",
            {"source_revision": "a" * 64, "evidence_refs": [{}], "change_ref": "approved-change"},
        ),
    ],
)
def test_model_arguments_cannot_expand_actor_resource_or_command_scope(name, args):
    tools, handler, _, _, _ = case()
    with pytest.raises(ValueError):
        tools.invoke(name, args)
    handler.assert_not_called()


def test_invalid_json_and_duplicate_arguments_consume_the_same_bounded_budget():
    tools, handler, _, _, _ = case(max_calls=2)
    for raw in ("{", '{"environment_ref":"aws-prod","environment_ref":"vm-target"}'):
        with pytest.raises(ValueError):
            tools.invoke_json("get_environment_capabilities", raw)
    with pytest.raises(ValueError, match="budget"):
        tools.invoke("get_system_inventory", {})
    handler.assert_not_called()


def test_revocation_after_handler_suppresses_result_and_halts_further_work():
    tools, handler, membership, _, _ = case()
    membership.side_effect = [tools.principal, None]
    with pytest.raises(RuntimeError, match="blocked"):
        tools.invoke("get_system_inventory", {})
    assert tools.halted.is_set() and handler.call_count == 1
    with pytest.raises(RuntimeError, match="reconciliation"):
        tools.invoke("get_system_inventory", {})
    assert handler.call_count == 1


def test_handler_failure_or_foreign_artifact_never_leaks_diagnostics_or_grants_refs():
    tools, handler, _, _, artifact = case()
    ref = "evidence-" + "c" * 64
    handler.return_value = InvestigationReceipt("metadata", ("source_verified",), (ref,))
    artifact.return_value = False
    with pytest.raises(RuntimeError, match="ownership"):
        tools.invoke("get_system_inventory", {})
    assert ref not in tools.references["evidence"] and tools.halted.is_set()
    tools, handler, _, _, _ = case()
    handler.side_effect = OSError("secret-canary-never-return")
    with pytest.raises(RuntimeError) as error:
        tools.invoke("get_system_inventory", {})
    assert "secret-canary" not in str(error.value) and tools.halted.is_set()


def test_new_refs_require_current_artifact_ownership_and_proposals_cannot_execute():
    tools, _, _, _, artifact = case()
    handlers = dict(tools.handlers)
    ref = "proposal-" + "c" * 64
    handlers["propose_change"] = Mock(
        return_value=InvestigationReceipt("proposal_only", ("proposal_only",), (ref,))
    )
    tools.handlers = handlers
    tools.invoke(
        "propose_change",
        {
            "source_revision": "a" * 64,
            "evidence_refs": ["evidence-" + "a" * 64],
            "change_ref": "approved-change",
        },
    )
    assert ref in tools.references["proposal"]
    artifact.assert_called_with(tools.principal, tools.scope, ref)
    handlers["propose_change"].return_value = InvestigationReceipt("metadata", ("source_verified",))
    with pytest.raises(ValueError, match="cannot claim"):
        tools.invoke(
            "propose_change",
            {
                "source_revision": "a" * 64,
                "evidence_refs": ["evidence-" + "a" * 64],
                "change_ref": "approved-change",
            },
        )


def test_deadline_missing_capability_and_public_receipt_contract():
    clock = [0.0]
    tools, handler, _, _, _ = case(clock=lambda: clock[0])
    assert tools.invoke("get_environment_capabilities", {"environment_ref": "aws-prod"}).status == "blocked"
    clock[0] = 61
    with pytest.raises(TimeoutError):
        tools.invoke("get_system_inventory", {})
    handler.assert_not_called()
    with pytest.raises(ValueError):
        InvestigationReceipt("deployed", ("source_verified",))
    with pytest.raises(ValueError):
        InvestigationReceipt("metadata", ("password-secret-value",))
    with pytest.raises(ValueError):
        InvestigationReceipt("metadata", (), ("postgresql://password@host",))
