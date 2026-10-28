"""Compare trusted, bounded app-read measurements without claiming causality.

There is no HTTP endpoint accepting measurement values. A registered observer
records these summaries after running against the exact two workload bindings.
Raw samples stay in evidence storage, not the deployment metadata document.
"""

import math
import re
from copy import deepcopy
from datetime import datetime

from application.deployment_writes import DeploymentMetadataWriter
from application.operating_review import deployment_observation_binding
from application.security_hold import require_no_security_hold

_KEYS = {
    "schema_version",
    "binding",
    "source_revision",
    "image_digest",
    "workload_sha256",
    "dataset_sha256",
    "concurrency",
    "samples",
    "successes",
    "failures",
    "duration_seconds",
    "p50_ms",
    "p95_ms",
    "throughput_rps",
    "started_at",
    "finished_at",
    "evidence_ref",
    "scope",
}


def validate_window(value):
    if (
        not isinstance(value, dict)
        or set(value) != _KEYS
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
    ):
        raise ValueError("Versioned trusted measurement required")
    from domain.database import DatabaseBinding

    DatabaseBinding(**value["binding"])
    for key in ("source_revision", "workload_sha256", "dataset_sha256"):
        if not isinstance(value[key], str) or not re.fullmatch(r"[a-f0-9]{64}", value[key]):
            raise ValueError("Pinned benchmark identity required")
    if not (value["scope"] == "postgresql_application_read" and value["image_digest"] is None) and (
        not isinstance(value["image_digest"], str)
        or not re.fullmatch(r"sha256:[a-f0-9]{64}", value["image_digest"])
    ):
        raise ValueError("Same execution image digest required")
    if (
        any(type(value[key]) is not int for key in ("concurrency", "samples", "successes", "failures"))
        or not 1 <= value["concurrency"] <= 16
        or not 30 <= value["samples"] <= 5000
        or value["successes"] < 1
        or value["failures"] < 0
        or value["successes"] + value["failures"] != value["samples"]
    ):
        raise ValueError("Bounded and complete benchmark counts required")
    for key in ("duration_seconds", "p50_ms", "p95_ms", "throughput_rps"):
        if type(value[key]) not in (int, float) or not math.isfinite(value[key]) or value[key] < 0:
            raise ValueError("Finite benchmark measurements required")
    start, end = (datetime.fromisoformat(value[key]) for key in ("started_at", "finished_at"))
    if (
        start.tzinfo is None
        or end.tzinfo is None
        or not 10 <= value["duration_seconds"] <= 600
        or abs((end - start).total_seconds() - value["duration_seconds"]) > 2
        or value["p50_ms"] > value["p95_ms"]
        or not math.isclose(
            value["throughput_rps"],
            value["successes"] / value["duration_seconds"],
            rel_tol=0.01,
            abs_tol=0.01,
        )
        or value["scope"] not in {"postgresql_application_read", "https_application_read"}
        or not isinstance(value["evidence_ref"], str)
        or not re.fullmatch(r"evidence:[A-Za-z0-9/_-]{1,200}", value["evidence_ref"])
    ):
        raise ValueError("Consistent measurement interval and evidence required")
    return start, end


def compare_windows(before, after, *, source, target, source_revision, image_digest, now):
    _, left_end = validate_window(before)
    right_start, right_end = validate_window(after)
    current = datetime.fromisoformat(now)
    if (
        current.tzinfo is None
        or left_end > right_start
        or not 0 <= (current - right_end).total_seconds() <= 7200
        or before["binding"] != source
        or after["binding"] != target
        or any(
            before[key] != after[key]
            for key in (
                "source_revision",
                "image_digest",
                "workload_sha256",
                "dataset_sha256",
                "concurrency",
                "samples",
                "scope",
            )
        )
        or before["source_revision"] != source_revision
        or before["image_digest"] != image_digest
    ):
        raise ValueError("Comparable current before/after deployment measurements required")
    left_error, right_error = before["failures"] / before["samples"], after["failures"] / after["samples"]
    change = (after["p95_ms"] / before["p95_ms"] - 1) * 100 if before["p95_ms"] > 0 else None
    outcome = (
        "inconclusive"
        if change is None
        else "regressed_in_observed_window"
        if right_error > left_error or change > 10
        else "improved_in_observed_window"
        if right_error <= left_error and change < -10
        else "no_clear_change_in_observed_window"
    )
    return {
        "status": "measured",
        "scope": before["scope"],
        "outcome": outcome,
        "p95_change_percent": change,
        "before": deepcopy(before),
        "after": deepcopy(after),
        "before_error_rate": left_error,
        "after_error_rate": right_error,
        "causal_improvement_proven": False,
        "production_capacity_proven": False,
        "application_image_compared": before["image_digest"] is not None,
        "automatic_action": False,
    }


class PromotionPerformanceReview:
    def __init__(self, records, operations):
        self.writer, self.operations = DeploymentMetadataWriter(records), operations

    def record(self, principal, job_id, operation_id, before, after, *, now):
        snapshot = self.writer.snapshot(principal, job_id)
        job = snapshot.record
        require_no_security_hold(job)
        promotion = job.get("database_promotion")
        operation = self.operations.get(operation_id)
        if (
            not isinstance(promotion, dict)
            or promotion.get("operation_id") != operation_id
            or operation.kind != "db_dedicated_cutover"
            or operation.status != "succeeded"
            or operation.application_id != job["application_id"]
            or operation.result != promotion
            or promotion.get("binding") != job.get("workload_database_binding")
            or promotion.get("active_runtime", {}).get("image_digest")
            != job.get("result", {}).get("image_digest")
        ):
            raise ValueError("Exact completed and published promotion required")
        comparison = compare_windows(
            before,
            after,
            source=promotion["baseline"]["source"],
            target=promotion["binding"],
            source_revision=job["source_digest"],
            image_digest=None
            if before["scope"] == "postgresql_application_read" and before["image_digest"] is None
            else job["result"]["image_digest"],
            now=now,
        )
        report = {
            **comparison,
            "operation_id": operation_id,
            "reviewed_at": now,
            "deployment_binding": deployment_observation_binding(job),
        }
        self.writer.patch(principal, job_id, snapshot.revision, {"promotion_performance_review": report})
        return report
