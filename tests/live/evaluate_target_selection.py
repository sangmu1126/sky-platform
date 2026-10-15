"""Opt-in model evaluation of fixed synthetic projects; never deploy resources.

Run from the repository root with `python -m tests.live.evaluate_target_selection`.
Default mode evaluates deterministic gates only. --live also calls the configured
OpenAI model for eligible HTTP cases. Cloud availability is a declared fixture,
not a claim that credentials or runtime resources have been verified.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from application.analysis import AISettings, AnalysisError
from application.deployment_core import source_digest
from application.infrastructure import (
    INFRA_INSTRUCTIONS,
    INFRA_SCHEMA,
    OpenAIInfrastructurePlanner,
    inspect_infrastructure,
    plan_infrastructure,
)
from engine.candidates import SUPPORTED_TARGETS, compare_targets
from engine.static_site import assess_static_site

CASES = Path(__file__).parents[1] / "fixtures/evaluation/target-selection.json"


def run_case(case: dict, planner=None) -> dict:
    with tempfile.TemporaryDirectory(prefix="sky-target-eval-") as directory:
        project = Path(directory)
        for name, contents in case["files"].items():
            (project / name).write_text(contents)
        profile = inspect_infrastructure(project)
        _, candidates = compare_targets(
            profile,
            dict.fromkeys(SUPPORTED_TARGETS),
            public_access=case["public_access"],
            public_url_required=case["public_url_required"],
        )
        static = assess_static_site(project, profile)
        if case["public_access"] and static.status == "eligible":
            route, targets = "static", ["aws-s3-cloudfront"]
        else:
            targets = [item["id"] for item in candidates if item["status"] == "eligible"]
            route = "model" if targets else "blocked"
        comparisons = {item["id"]: item for item in candidates}
        checks = {
            "route": route == case["expected_route"],
            "eligible_targets": set(targets) == set(case["expected_targets"]),
        }
        if expected := case.get("expected_comparison"):
            actual = comparisons[expected["target"]]
            checks["structural_status"] = actual["structural_status"] == expected["structural_status"]
            checks["native_workload_status"] = (
                actual["native_adapter"]["workload_status"] == expected["native_workload_status"]
            )
        result = {
            "case": case["id"],
            "source_digest": source_digest(project),
            "route": route,
            "eligible_targets": targets,
            "checks": checks,
            "candidate_assessments": [
                {
                    "target": item["id"],
                    "status": item["status"],
                    "structural_status": item["structural_status"],
                    "reason_codes": item["reason_codes"],
                    "native_workload_status": (item.get("native_adapter") or {}).get("workload_status"),
                }
                for item in candidates
            ],
            "rules_passed": all(checks.values()),
            "model_status": "not_applicable",
            "model_attempts": 0,
            "model_seconds": None,
        }
        if route != "model" or not result["rules_passed"]:
            return result
        if planner is None:
            result["model_status"] = "not_run"
            return result

        class CountedPlanner:
            def propose(self, *args, **kwargs):
                result["model_attempts"] += 1
                return planner.propose(*args, **kwargs)

        started = time.monotonic()
        try:
            plan = plan_infrastructure(project, targets, case["public_access"], CountedPlanner())
            result.update(
                model_status="passed",
                selected_target=plan["target"],
                rationale=plan["rationale"],
                evidence=plan["evidence"],
            )
        except AnalysisError:
            # Do not persist raw model errors, which may echo untrusted content.
            result.update(model_status="failed", failure="model_response_rejected")
        except (OSError, ValueError):
            result.update(model_status="failed", failure="planner_failed")
        finally:
            result["model_seconds"] = round(time.monotonic() - started, 3)
        return result


def run_evaluation(planner=None, *, cases=None, model=None) -> dict:
    selected = json.loads(CASES.read_text()) if cases is None else cases
    results = [run_case(case, planner) for case in selected]
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "mode": "live" if planner is not None else "rules_only",
        "model": model if planner is not None else None,
        "prompt_sha256": hashlib.sha256(INFRA_INSTRUCTIONS.encode()).hexdigest(),
        "schema_sha256": hashlib.sha256(json.dumps(INFRA_SCHEMA, sort_keys=True).encode()).hexdigest(),
        "dataset_sha256": hashlib.sha256(json.dumps(selected, sort_keys=True).encode()).hexdigest(),
        "availability": "synthetic: all container targets and static hosting configured",
        "case_count": len(results),
        "rules_passed": sum(item["rules_passed"] for item in results),
        "model_evaluated": sum(item["model_status"] in {"passed", "failed"} for item in results),
        "model_failed": sum(item["model_status"] == "failed" for item in results),
        "model_attempts": sum(item["model_attempts"] for item in results),
        "deployment_verified": False,
        "limitations": [
            "Synthetic fixtures; not production traffic or a unique optimal-backend benchmark.",
            "Model checks cover allowed target, workload and exact source citation; human review of reasoning remains required.",
            "Rules-only results do not evaluate a model. Static and blocked cases do not call a model.",
            "No build, cloud provisioning, database or HTTP runtime verification occurs.",
        ],
        "cases": results,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="Call OpenAI for eligible synthetic HTTP cases")
    options = parser.parse_args(argv)
    settings = AISettings.from_environment()
    if options.live and not settings.available:
        parser.error("--live requires OPENAI_API_KEY; no model calls were made")
    planner = OpenAIInfrastructurePlanner(settings) if options.live else None
    report = run_evaluation(planner, model=settings.model)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return int(report["rules_passed"] != report["case_count"] or report["model_failed"] > 0)


if __name__ == "__main__":
    raise SystemExit(main())
