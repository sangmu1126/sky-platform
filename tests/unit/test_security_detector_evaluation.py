from unittest.mock import patch

import pytest

from application.security_detector_evaluation import evaluate_secret_detector


def test_replay_measures_false_positives_missed_events_and_unavailable_collection():
    with patch("boto3.Session", side_effect=AssertionError("No live AWS in replay")):
        report = evaluate_secret_detector(repetitions=3)
    assert report["passed"]
    assert report["totals"] == {
        "true_positive": 6,
        "true_negative": 21,
        "false_positive": 0,
        "false_negative": 0,
        "incomplete_not_treated_as_healthy": 6,
        "duplicate_events_deduplicated": 3,
    }
    assert not report["holds_or_releases_executed"]
    assert not report["population_detection_or_sla_claimed"]


def test_incorrect_detector_cannot_be_reported_as_success():
    def missing(*_, **__):
        return {
            "collection_complete": False,
            "matching_successful_forbidden_reads": [],
            "absence_of_compromise_proven": False,
        }

    with patch(
        "application.security_detector_evaluation.CloudTrailSecretAccessMonitor.observe", side_effect=missing
    ):
        report = evaluate_secret_detector(repetitions=1)
    assert not report["passed"] and report["totals"]["false_negative"] == 2


@pytest.mark.parametrize("count", [0, 101, True])
def test_replay_work_is_bounded(count):
    with pytest.raises(ValueError):
        evaluate_secret_detector(repetitions=count)
