from dataclasses import asdict

import pytest

from application.database_cutover import DatabaseCutover
from domain.database import DatabaseBinding


class Fence:
    def __init__(self, binding):
        self.binding = binding
        self.enabled = True

    def set_login(self, enabled, *, guard):
        guard()
        self.enabled = enabled
        return {"login_enabled": enabled}


class Traffic:
    def __init__(self, binding):
        self.binding = binding
        self.closed = False
        self.fail = False

    def quiesce(self, expected):
        assert self.binding == expected
        self.closed = True

    def activate(self, expected, target):
        assert self.closed and self.binding == expected
        self.binding = target

    def probe(self, target):
        assert self.closed and self.binding == target
        if self.fail:
            raise ValueError("unhealthy")

    def resume(self, target):
        assert self.closed and self.binding == target
        self.closed = False


class Sync:
    def refresh(self, plan, *, expected_destination, guard, reverse=False):
        guard()
        return {**expected_destination, "reverse": reverse}


def fixture():
    source_binding = DatabaseBinding(
        "org", "app", "shared_workload", "111111111111", "ap-northeast-2", "pool", "app_db", "source-owner"
    )
    target_binding = DatabaseBinding(
        "org",
        "app",
        "dedicated_workload",
        "111111111111",
        "ap-northeast-2",
        "dedicated",
        "app_db",
        "target-owner",
    )
    source, target, traffic, events = (
        Fence(source_binding),
        Fence(target_binding),
        Traffic(asdict(source_binding)),
        [],
    )
    flow = DatabaseCutover(Sync(), source, target, traffic, guard=lambda: None, journal=events.append)
    return flow, source, target, traffic, events


def test_single_writer_and_explicit_reverse_recovery():
    flow, source, target, traffic, events = fixture()
    plan = {"plan_id": "test", "source": asdict(source.binding), "target": asdict(target.binding)}
    result = flow.promote(plan, plan)
    assert not source.enabled and target.enabled and not traffic.closed
    flow.rollback(plan, result["baseline"])
    assert source.enabled and not target.enabled and traffic.binding == plan["source"] and not traffic.closed
    assert any(e["stage"] == "reverse_sync" and e["status"] == "observed" for e in events)


def test_failed_probe_keeps_writes_closed_until_explicit_recovery():
    flow, source, target, traffic, events = fixture()
    traffic.fail = True
    plan = {"plan_id": "test", "source": asdict(source.binding), "target": asdict(target.binding)}
    with pytest.raises(ValueError, match="unhealthy"):
        flow.promote(plan, plan)
    assert traffic.closed and not source.enabled
    final = next(e["receipt"] for e in events if e["stage"] == "final_sync" and e["status"] == "observed")
    traffic.fail = False
    flow.rollback(plan, final)
    assert source.enabled and not target.enabled and not traffic.closed


def test_journal_failure_prevents_next_external_effect():
    flow, source, target, traffic, _events = fixture()

    def fail(event):
        raise RuntimeError("storage unavailable")

    flow.journal = fail
    plan = {"plan_id": "test", "source": asdict(source.binding), "target": asdict(target.binding)}
    with pytest.raises(RuntimeError):
        flow.promote(plan, plan)
    assert not traffic.closed and source.enabled and target.enabled


def test_foreign_baseline_rejected_before_fencing_or_quiesce():
    flow, source, target, traffic, _events = fixture()
    plan = {"plan_id": "test", "source": asdict(source.binding), "target": asdict(target.binding)}
    with pytest.raises(ValueError, match="baseline"):
        flow.promote(plan, {**plan, "plan_id": "foreign"})
    assert source.enabled and target.enabled and not traffic.closed


@pytest.mark.parametrize(
    "change",
    [
        {"account_id": "222222222222"},
        {"region": "ap-northeast-1"},
        {"application_id": "foreign"},
        {"organization_id": "foreign"},
        {"role": "sky_state"},
        {"instance_id": "pool"},
    ],
)
def test_unsupported_route_rejected_before_any_external_effect(change):
    from dataclasses import replace

    flow, source, target, traffic, events = fixture()
    target.binding = replace(target.binding, **change)
    plan = {"plan_id": "test", "source": asdict(source.binding), "target": asdict(target.binding)}
    with pytest.raises(ValueError, match="registered cutover"):
        flow.promote(plan, plan)
    assert source.enabled and target.enabled and not traffic.closed
    assert events == []


def test_provider_neutral_review_plan_cannot_be_submitted_to_legacy_executor():
    from domain.database_migration import DatabaseLocation, DatabasePlacement, MigrationSafetyPolicy
    from engine.database_migration import plan_database_migration

    flow, source, target, traffic, events = fixture()
    placement = DatabasePlacement(
        "org",
        "app",
        "shared_workload",
        DatabaseLocation("aws", "rds_postgresql", "111111111111", "ap-northeast-2"),
        "pool",
        "app_db",
        "owner",
        16,
    )
    from dataclasses import replace

    review = plan_database_migration(
        placement,
        replace(placement, role="dedicated_workload", instance_id="dedicated"),
        MigrationSafetyPolicy(120, 600, 86400),
        source_revision="a" * 64,
    )
    with pytest.raises(TypeError):
        flow.promote(review, review)
    assert source.enabled and target.enabled and not traffic.closed
    assert events == []


def test_read_preserving_mode_requires_two_explicit_write_fences():
    flow, source, target, traffic, _ = fixture()
    with pytest.raises(TypeError, match="Both registered"):
        DatabaseCutover(
            flow.sync,
            source,
            target,
            traffic,
            guard=lambda: None,
            journal=lambda _: None,
            preserve_reads=True,
        )


def test_read_mode_enables_writes_only_after_route_probe():
    from adapters.database.promotion_write_fence import PostgresPromotionWriteFence

    flow, source, target, traffic, events = fixture()

    class WriteFence(PostgresPromotionWriteFence):
        def __init__(self, binding):
            self.binding, self.enabled = binding, True

        def set_writes(self, enabled, *, guard):
            guard()
            self.enabled = enabled
            return {"writes_enabled": enabled, "login_enabled": True}

        def set_login(self, enabled, *, guard):
            raise AssertionError("Planned read-preserving migration must not change LOGIN")

    source, target = WriteFence(source.binding), WriteFence(target.binding)
    flow = DatabaseCutover(
        flow.sync, source, target, traffic, guard=lambda: None, journal=events.append, preserve_reads=True
    )
    plan = {"plan_id": "test", "source": asdict(source.binding), "target": asdict(target.binding)}
    result = flow.promote(plan, plan)
    stages = [x["stage"] for x in events if x["status"] == "observed"]
    assert stages.index("probe_target") < stages.index("enable_target") < stages.index("resume_target")
    assert not source.enabled and target.enabled
    events.clear()
    flow.rollback(plan, result["baseline"])
    stages = [x["stage"] for x in events if x["status"] == "observed"]
    assert stages.index("probe_source") < stages.index("enable_source") < stages.index("resume_source")
    assert source.enabled and not target.enabled
