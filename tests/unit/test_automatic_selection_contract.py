"""The model is offered only the automatic execution contract for this request."""

import io
import json
from copy import deepcopy
from unittest.mock import patch

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
