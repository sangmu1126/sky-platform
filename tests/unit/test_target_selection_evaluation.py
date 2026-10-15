"""Eval results distinguish rule coverage, actual model checks and deployment proof."""

import json
from unittest.mock import Mock, patch

import pytest

from tests.live.evaluate_target_selection import CASES, main, run_case, run_evaluation

DATASET = json.loads(CASES.read_text())


class GroundedPlanner:
    def propose(self, files, targets, public, **kwargs):
        path, source = next(iter(files.items()))
        return {
            "target": targets[0],
            "workload": "stateless-http",
            "rationale": "검증용 모의 판단",
            "evidence": [{"file": path, "quote": source[:40]}],
        }


@pytest.mark.parametrize("case", DATASET, ids=lambda case: case["id"])
def test_fixed_cases_match_current_candidate_rules_without_model_calls(case):
    result = run_case(case)
    assert result["rules_passed"] is True
    assert result["model_status"] in {"not_run", "not_applicable"}
    assert result["model_attempts"] == 0


def test_rule_report_does_not_claim_model_or_runtime_validation():
    result = run_evaluation()
    assert result["mode"] == "rules_only"
    assert result["rules_passed"] == result["case_count"] == 10
    assert result["model_evaluated"] == result["model_failed"] == result["model_attempts"] == 0
    assert result["deployment_verified"] is False
    assert result["model"] is None
    assert len(result["prompt_sha256"]) == len(result["schema_sha256"]) == len(result["dataset_sha256"]) == 64


def test_model_only_receives_eligible_cases_and_server_validates_its_outputs():
    planner = Mock(wraps=GroundedPlanner())
    result = run_evaluation(planner, model="fixture-model")
    assert planner.propose.call_count == result["model_evaluated"] == 4
    assert result["model_failed"] == 0
    assert result["model_attempts"] == 4
    for item in result["cases"]:
        if item["model_status"] == "passed":
            assert item["selected_target"] in item["eligible_targets"]
            assert item["evidence"]
        else:
            assert item["model_attempts"] == 0


@pytest.mark.parametrize(
    "invalid",
    [
        {"target": "aws-ec2"},
        {"workload": "requires-unsupported-resources"},
        {"evidence": [{"file": "invented.py", "quote": "invented"}]},
    ],
)
def test_rejected_model_output_is_failed_and_never_counted_as_success(invalid):
    class InvalidPlanner(GroundedPlanner):
        def propose(self, *args, **kwargs):
            return {**super().propose(*args, **kwargs), **invalid}

    result = run_case(DATASET[0], InvalidPlanner())
    assert result["rules_passed"] is True
    assert result["model_status"] == "failed"
    assert "selected_target" not in result
    assert result["model_attempts"] == (2 if "evidence" in invalid else 1)


def test_rule_mismatch_stops_model_evaluation():
    planner = Mock()
    result = run_case({**DATASET[0], "expected_targets": []}, planner)
    assert result["rules_passed"] is False
    planner.propose.assert_not_called()


def test_default_cli_cannot_accidentally_call_model(capsys):
    with patch("tests.live.evaluate_target_selection.OpenAIInfrastructurePlanner") as planner:
        assert main([]) == 0
        planner.assert_not_called()
    assert json.loads(capsys.readouterr().out)["model_evaluated"] == 0


def test_live_cli_with_missing_key_fails_before_calls(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with patch("tests.live.evaluate_target_selection.OpenAIInfrastructurePlanner") as planner:
        with pytest.raises(SystemExit) as exit_info:
            main(["--live"])
        assert exit_info.value.code == 2
        planner.assert_not_called()
