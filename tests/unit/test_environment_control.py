import importlib.util
from dataclasses import asdict
from pathlib import Path
from unittest.mock import Mock

import pytest

from adapters.database.environment_control import EnvironmentApplicationControl
from tests.unit.test_database_transfer import transfer


def workload():
    spec = importlib.util.spec_from_file_location(
        "environment_demo", Path(__file__).parents[1] / "fixtures/environment_transfer/server.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    app = module.Workload({"binding": asdict(transfer().source), "controller_id": "source-app"})
    app.read = Mock(return_value={"rows": []})
    return app


def client(app):
    return EnvironmentApplicationControl(
        transfer(),
        "https://registered.test/control",
        "secret",
        controller_id="source-app",
        guard=lambda: None,
        transport=app.control,
    )


def test_restart_closed_requires_verified_read_and_refuses_stale_generation():
    app = workload()
    controller = client(app)
    assert app.closed
    controller.quiesce(app.binding)
    with pytest.raises(ValueError, match="Verified"):
        controller.resume(app.binding)
    controller.probe(app.binding)
    controller.resume(app.binding)
    assert not app.closed and app.read.call_count == 1
    controller.quiesce(app.binding)
    app.generation += 1  # A restart or different admitted controller invalidates this client's state.
    with pytest.raises(RuntimeError, match="reconciliation"):
        controller.probe(app.binding)
    assert app.closed and controller.uncertain


def test_failed_database_probe_never_opens_writers_or_retries_control():
    app = workload()
    app.read.side_effect = OSError("do-not-expose-credentials")
    controller = client(app)
    controller.quiesce(app.binding)
    with pytest.raises(RuntimeError, match="reconciliation") as error:
        controller.probe(app.binding)
    assert "do-not-expose" not in str(error.value)
    assert app.closed and not app.probed
    with pytest.raises(RuntimeError, match="reconcile"):
        controller.quiesce(app.binding)
    assert app.read.call_count == 1


def test_fixed_revision_cannot_rebind_database_or_accept_replayed_command():
    app = workload()
    controller = client(app)
    commands = []

    def record(command):
        commands.append(command)
        return app.control(command)

    controller.transport = record
    controller.quiesce(app.binding)
    with pytest.raises(ValueError, match="replayed"):
        app.control(commands[0])
    with pytest.raises(ValueError, match="fixed database"):
        controller.activate(app.binding, asdict(transfer().target))
    assert len(commands) == 1 and app.closed
