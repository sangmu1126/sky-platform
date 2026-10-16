"""The model is offered only the automatic execution contract for this request."""

import io
import json
from copy import deepcopy
from unittest.mock import Mock, patch

import pytest

from application.analysis import AISettings, AnalysisError
from application.infrastructure import (
    INFRA_SCHEMA,
    OpenAIInfrastructurePlanner,
    validate_infrastructure_proposal,
)
from engine.target_selection_context import automatic_target_context


def proposal(target):
    return {
        "target": target,
        "workload": "stateless-http",
        "rationale": "HTTP 컨테이너 후보 비교",
        "evidence": [{"file": "app.py", "quote": "hello"}],
    }


def response(target):
    return io.BytesIO(
        json.dumps(
            {
                "status": "completed",
                "output": [
                    {
                        "type": "message",
                        "content": [
                            {"type": "output_text", "text": json.dumps(proposal(target))},
                        ],
                    }
                ],
            }
        ).encode()
    )


def test_response_enum_matches_offered_targets_and_is_request_local():
    original_schema = deepcopy(INFRA_SCHEMA)
    planner = OpenAIInfrastructurePlanner(AISettings("fixture-key", "fixture-model"))
    with patch("application.infrastructure.urllib.request.build_opener") as opener:
        opener.return_value.open.side_effect = [response("local-docker"), response("cloud-run")]
        planner.propose({"app.py": "hello"}, ["local-docker"], False)
        planner.propose({"app.py": "hello"}, ["cloud-run", "aws-ecs-express"], True)
        payloads = [json.loads(call.args[0].data) for call in opener.return_value.open.call_args_list]
    for payload, targets in zip(payloads, [["local-docker"], ["cloud-run", "aws-ecs-express"]]):
        inputs = json.loads(payload["input"])
        assert inputs["available_targets"] == targets
        assert [candidate["target"] for candidate in inputs["candidates"]] == targets
        assert payload["text"]["format"]["schema"]["properties"]["target"]["enum"] == targets
    assert INFRA_SCHEMA == original_schema


@pytest.mark.parametrize(
    "targets,public",
    [
        ([], False),
        (["local-docker", "local-docker"], False),
        (["aws-lambda"], True),
        (["aws-ec2"], True),
        (["onprem-compose"], False),
        (["aws-ecs-express"], False),
        (["local-docker", {}], False),
        ("local-docker", False),
        (["local-docker"], "true"),
    ],
)
def test_invalid_or_explicit_only_choices_never_reach_the_api(targets, public):
    planner = OpenAIInfrastructurePlanner(AISettings("fixture-key", "fixture-model"))
    with patch("application.infrastructure.read_response") as request:
        with pytest.raises(ValueError):
            planner.propose({"app.py": "hello"}, targets, public)
        request.assert_not_called()


def test_explicit_database_support_is_not_automatic_database_permission():
    for candidate in automatic_target_context(["cloud-run", "aws-ecs-express"], True):
        assert candidate["explicit_postgresql_binding"] is True
        assert candidate["automatic_path_supports_database"] is False
        assert "database" in candidate["unsupported_requirements"]
        assert candidate["automatic_selection"] == {
            "eligible": True,
            "scope": "stateless_http_container",
            "adapter_support": "implemented",
            "runtime_verification": "pending",
        }


def test_server_rejects_an_unoffered_choice_even_if_model_returns_valid_global_target():
    with pytest.raises(AnalysisError, match="사용할 수 없는"):
        validate_infrastructure_proposal(proposal("aws-ecs-express"), {"app.py": "hello"}, ["local-docker"])


def test_public_url_requirement_is_transmitted_and_retained_after_citation_retry(tmp_path):
    from application.infrastructure import plan_infrastructure

    (tmp_path / "app.py").write_text("hello")
    planner = Mock()
    invalid = {**proposal("aws-ecs-express"), "evidence": [{"file": "app.py", "quote": "invented"}]}
    planner.propose.side_effect = [invalid, proposal("aws-ecs-express")]
    result = plan_infrastructure(
        tmp_path,
        ["aws-ecs-express"],
        True,
        planner,
        public_url_required=True,
    )
    assert result["selection_conditions"] == {"public_access_allowed": True, "public_url_required": True}
    assert [call.kwargs for call in planner.propose.call_args_list] == [
        {"public_url_required": True},
        {"retry_invalid_evidence": True, "public_url_required": True},
    ]


def test_model_request_records_explicit_public_url_requirement():
    planner = OpenAIInfrastructurePlanner(AISettings("fixture-key", "fixture-model"))
    with patch("application.infrastructure.urllib.request.build_opener") as opener:
        opener.return_value.open.return_value = response("aws-ecs-express")
        planner.propose({"app.py": "hello"}, ["aws-ecs-express"], True, public_url_required=True)
        payload = json.loads(opener.return_value.open.call_args.args[0].data)
    assert json.loads(payload["input"])["selection_conditions"] == {
        "public_access_allowed": True,
        "public_url_required": True,
    }


@pytest.mark.parametrize(
    "targets,public,required",
    [
        (["local-docker"], True, True),
        (["cloud-run"], False, True),
        (["aws-ecs-express"], True, "true"),
    ],
)
def test_application_rejects_inconsistent_conditions_before_injected_planner(
    tmp_path, targets, public, required
):
    from application.infrastructure import plan_infrastructure

    (tmp_path / "app.py").write_text("hello")
    planner = Mock()
    with pytest.raises(ValueError):
        plan_infrastructure(tmp_path, targets, public, planner, public_url_required=required)
    planner.propose.assert_not_called()
