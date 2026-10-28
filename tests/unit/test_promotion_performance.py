from copy import deepcopy
from datetime import datetime, timedelta

import pytest

from application.promotion_performance import compare_windows, validate_window

NOW = "2026-10-28T01:00:00+00:00"
SOURCE = {
    "organization_id": "org",
    "application_id": "app",
    "role": "shared_workload",
    "account_id": "111111111111",
    "region": "ap-northeast-2",
    "instance_id": "pool",
    "database_name": "app",
    "owner_ref": "owned",
}
TARGET = {**SOURCE, "role": "dedicated_workload", "instance_id": "dedicated"}


def windows():
    start = datetime.fromisoformat(NOW) - timedelta(minutes=5)
    before = {
        "schema_version": 1,
        "binding": SOURCE,
        "source_revision": "a" * 64,
        "image_digest": "sha256:" + "b" * 64,
        "workload_sha256": "c" * 64,
        "dataset_sha256": "d" * 64,
        "concurrency": 4,
        "samples": 100,
        "successes": 100,
        "failures": 0,
        "duration_seconds": 30,
        "p50_ms": 10,
        "p95_ms": 20,
        "throughput_rps": 100 / 30,
        "started_at": start.isoformat(),
        "finished_at": (start + timedelta(seconds=30)).isoformat(),
        "evidence_ref": "evidence:native/before",
        "scope": "postgresql_application_read",
    }
    after = {
        **deepcopy(before),
        "binding": TARGET,
        "p50_ms": 5,
        "p95_ms": 10,
        "started_at": (start + timedelta(seconds=60)).isoformat(),
        "finished_at": (start + timedelta(seconds=90)).isoformat(),
        "evidence_ref": "evidence:native/after",
    }
    return before, after


def compare(before, after):
    return compare_windows(
        before,
        after,
        source=SOURCE,
        target=TARGET,
        source_revision="a" * 64,
        image_digest="sha256:" + "b" * 64,
        now=NOW,
    )


def test_measured_difference_does_not_claim_causality_or_capacity():
    before, after = windows()
    result = compare(before, after)
    assert result["outcome"] == "improved_in_observed_window" and result["p95_change_percent"] == -50
    assert (
        not result["causal_improvement_proven"]
        and not result["production_capacity_proven"]
        and not result["automatic_action"]
    )
    after["p95_ms"] = 25
    assert compare(before, after)["outcome"] == "regressed_in_observed_window"
    after["p95_ms"] = 20
    assert compare(before, after)["outcome"] == "no_clear_change_in_observed_window"


@pytest.mark.parametrize(
    "key,value",
    [
        ("image_digest", "sha256:" + "e" * 64),
        ("dataset_sha256", "e" * 64),
        ("source_revision", "e" * 64),
        ("concurrency", 8),
        ("samples", 101),
        ("scope", "https_application_read"),
        ("binding", SOURCE),
    ],
)
def test_changed_application_data_schedule_or_placement_is_not_comparable(key, value):
    before, after = windows()
    after[key] = value
    with pytest.raises(ValueError):
        compare(before, after)


@pytest.mark.parametrize(
    "key,value",
    [
        ("samples", True),
        ("failures", -1),
        ("duration_seconds", float("nan")),
        ("p95_ms", float("inf")),
        ("p50_ms", -1),
        ("throughput_rps", 100),
        ("evidence_ref", "arbitrary"),
    ],
)
def test_invalid_or_invented_measurements_rejected(key, value):
    before, _ = windows()
    before[key] = value
    with pytest.raises(ValueError):
        validate_window(before)


def test_old_and_out_of_order_evidence_rejected():
    before, after = windows()
    after["started_at"] = before["started_at"]
    after["finished_at"] = before["finished_at"]
    with pytest.raises(ValueError):
        compare(before, after)
    before, after = windows()
    with pytest.raises(ValueError):
        compare_windows(
            before,
            after,
            source=SOURCE,
            target=TARGET,
            source_revision="a" * 64,
            image_digest="sha256:" + "b" * 64,
            now="2026-10-29T01:00:00+00:00",
        )


def test_db_only_observer_does_not_claim_application_image_verification():
    before, after = windows()
    before["image_digest"] = after["image_digest"] = None
    result = compare_windows(
        before, after, source=SOURCE, target=TARGET, source_revision="a" * 64, image_digest=None, now=NOW
    )
    assert not result["application_image_compared"] and result["scope"] == "postgresql_application_read"
    before["scope"] = after["scope"] = "https_application_read"
    with pytest.raises(ValueError):
        compare_windows(
            before, after, source=SOURCE, target=TARGET, source_revision="a" * 64, image_digest=None, now=NOW
        )
