from copy import deepcopy
from dataclasses import replace

import pytest

from application.operating_review import deployment_observation_binding
from application.promotion_effect import PromotionEffectReview
from tests.unit.test_database_cutover_workflow import flow as flow  # noqa: PLC0414
from tests.unit.test_database_cutover_workflow import run
from tests.unit.test_deployment_writes import principal
from tests.unit.test_operating_review import ID, NOW

pytest_plugins = ["tests.unit.test_operating_review"]


def setup(flow):
    _, _, records, operations, _, _, traffic, _, operation, _ = flow
    target = operation.command["approval"]["proposal"]["plan"]["target"]
    active = {
        "service": "green",
        "service_arn": "arn:owned:green",
        "url": "https://stable",
        "image": "ecr@sha256:" + "a" * 64,
        "image_digest": "sha256:" + "a" * 64,
        "database": {"binding": target},
        "image_identity": {"status": "passed"},
        "traffic_strategy": "blue_green",
        "verification": {k: "verified" for k in ("http", "image", "database_authentication", "stable_route")},
    }
    active["verification"]["application_data_path"] = "read_verified"
    traffic.published_runtime = lambda _: deepcopy(active)
    assert run(flow)["status"] == "succeeded"
    operations.get.return_value = replace(
        operation, status="succeeded", result=deepcopy(records.job["database_promotion"])
    )
    records.health = [
        {
            "healthy": True,
            "checked_at": NOW,
            "deployment_binding": deployment_observation_binding(records.job),
        }
    ]
    return PromotionEffectReview(records, operations), records, operations, operation


def test_completed_loop_reports_placement_and_fresh_health_not_unmeasured_performance(flow):
    service, records, _, operation = setup(flow)
    report = service.review(principal(), ID, operation.id, now=NOW)
    assert report["placement"] == "dedicated_instance_verified"
    assert report["decision"] == "retain_and_observe"
    assert report["performance_improvement"] == "unverified"
    assert not report["automatic_action"] and not report["automation_reenabled"]
    assert records.job["promotion_effect_review"] == report


@pytest.mark.parametrize("fault", ["missing", "stale", "old_runtime", "failed"])
def test_missing_or_failed_health_never_claims_effect_verified(flow, fault):
    service, records, _, operation = setup(flow)
    if fault == "missing":
        records.health = []
    elif fault == "stale":
        records.health[0]["checked_at"] = "2026-10-10T00:00:00+00:00"
    elif fault == "old_runtime":
        records.health[0]["deployment_binding"] = {}
    else:
        records.health[0]["healthy"] = False
    report = service.review(principal(), ID, operation.id, now=NOW)
    assert report["decision"] == (
        "recovery_review_required" if fault == "failed" else "insufficient_evidence"
    )
    assert not report["automatic_action"]


@pytest.mark.parametrize("fault", ["wrong_operation", "unsettled", "different_runtime", "security_hold"])
def test_changed_or_restricted_deployment_is_not_reviewed(flow, fault):
    service, records, operations, operation = setup(flow)
    if fault == "wrong_operation":
        records.job["database_promotion"]["operation_id"] = "other"
    elif fault == "unsettled":
        operations.get.return_value = replace(operations.get.return_value, status="needs_attention")
    elif fault == "different_runtime":
        records.job["result"]["url"] = "https://other"
    else:
        records.job["security_hold"] = {"incident_id": "INC-owned"}
    with pytest.raises((ValueError, PermissionError)):
        service.review(principal(), ID, operation.id, now=NOW)
    assert "promotion_effect_review" not in records.job
