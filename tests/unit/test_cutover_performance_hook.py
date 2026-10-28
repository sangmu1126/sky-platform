from copy import deepcopy
from datetime import datetime, timedelta

from ports.promotion_performance import PromotionPerformanceObserver
from tests.unit.test_database_cutover_workflow import flow as flow  # noqa: PLC0414
from tests.unit.test_database_cutover_workflow import run
from tests.unit.test_operating_review import NOW
from tests.unit.test_promotion_performance import windows

pytest_plugins = ["tests.unit.test_operating_review"]


class Observer(PromotionPerformanceObserver):
    def __init__(self, flow, fail=False):
        self.flow, self.fail, self.calls = flow, fail, []

    def measure(self, plan, binding, *, guard):
        guard()
        self.calls.append(binding)
        if self.fail:
            raise OSError("Metrics unavailable; secret must not escape")
        before, after = windows()
        value = before if len(self.calls) == 1 else after
        start = datetime.fromisoformat(NOW) - timedelta(seconds=100 if len(self.calls) == 1 else 40)
        value.update(
            binding=deepcopy(binding),
            source_revision=plan["source_revision"],
            image_digest=None,
            started_at=start.isoformat(),
            finished_at=(start + timedelta(seconds=30)).isoformat(),
        )
        guard()
        return value


def test_registered_observer_is_called_before_and_after_and_bound_to_published_record(flow):
    worker, _, records, ops, *_ = flow
    worker.performance_observer = Observer(flow)
    assert run(flow)["status"] == "succeeded"
    report = records.job["promotion_performance_review"]
    assert report["status"] == "measured" and report["scope"] == "postgresql_application_read"
    assert report["outcome"] == "improved_in_observed_window" and not report["application_image_compared"]
    assert len(worker.performance_observer.calls) == 2
    from application.operating_review import deployment_observation_binding

    assert report["deployment_binding"] == deployment_observation_binding(records.job)
    assert ops.complete.call_count == 1


def test_optional_metrics_failure_does_not_hide_completed_cutover_or_invent_improvement(flow):
    worker, _, records, _, _, _, traffic, *_ = flow
    worker.performance_observer = Observer(flow, fail=True)
    assert run(flow)["status"] == "succeeded" and not traffic.closed
    report = records.job["promotion_performance_review"]
    assert report["status"] == "unverified" and "Metrics unavailable" not in str(report)
    assert "outcome" not in report and not report["automatic_action"]


def test_lost_execution_guard_during_measurement_still_holds_cutover(flow):
    worker, _, records, ops, _, _, traffic, *_ = flow

    class Lost(Observer):
        def measure(self, plan, binding, *, guard):
            ops.heartbeat.return_value = False
            guard()

    worker.performance_observer = Lost(flow)
    assert run(flow)["status"] == "needs_attention"
    assert traffic.binding == worker.registrations[next(iter(worker.registrations))]["source"]
    assert "database_promotion" not in records.job
