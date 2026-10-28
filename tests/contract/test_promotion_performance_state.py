from copy import deepcopy
from unittest.mock import Mock

from application.promotion_performance import PromotionPerformanceReview
from tests.contract.test_deployment_reads import setup as setup  # noqa: PLC0414
from tests.unit.test_database_cutover_workflow import flow as flow  # noqa: PLC0414
from tests.unit.test_deployment_writes import ID, principal
from tests.unit.test_promotion_effect import setup as promotion_setup
from tests.unit.test_promotion_performance import NOW, windows

pytest_plugins = ["tests.unit.test_operating_review"]


def test_trusted_measurement_summary_persists_with_exact_promotion_and_cas(setup, flow):
    records, _, _ = setup
    _, promoted, _, operation = promotion_setup(flow)
    records.save_job(ID, deepcopy(promoted.job))
    operations = Mock(get=Mock(return_value=operation))
    # setup returns the original queued fixture; effect setup retains the exact
    # completed operation on its mock store, so use its published result here.
    from dataclasses import replace

    operations.get.return_value = replace(
        operation, status="succeeded", result=deepcopy(promoted.job["database_promotion"])
    )
    before, after = windows()
    for value in (before, after):
        value["source_revision"] = promoted.job["source_digest"]
        value["image_digest"] = promoted.job["result"]["image_digest"]
    before["binding"] = promoted.job["database_promotion"]["baseline"]["source"]
    after["binding"] = promoted.job["workload_database_binding"]
    report = PromotionPerformanceReview(records, operations).record(
        principal(), ID, operation.id, before, after, now=NOW
    )
    stored = records.load_job(ID)
    assert stored.revision == 2 and stored.record["promotion_performance_review"] == report
    assert report["outcome"] == "improved_in_observed_window" and not report["automatic_action"]
    assert "samples.json" not in str(report)  # only bounded summary + evidence references
