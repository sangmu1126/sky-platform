"""Registered source is parsed without execution before runtime evidence is read."""

import hashlib
import json
from dataclasses import replace
from unittest.mock import Mock

import pytest

from adapters.source.workload_inventory import (
    RegisteredStaticSourceInventory,
    StaticSourceWorkloadInventoryReader,
    validate_static_source_inventory_report,
)
from application.deployment_core import source_digest
from ports.workload_inventory import WorkloadInventoryUnavailable
from tests.unit.test_environment_transition import NOW
from tests.unit.test_workload_inventory import registration, snapshot


def python_project(tmp_path):
    (tmp_path / "api.py").write_text(
        """import boto3
import psycopg
import requests
import websockets

s3 = boto3.client('s3')
"""
    )
    (tmp_path / "worker.py").write_text(
        """import boto3
import psycopg

s3 = boto3.client('s3')
"""
    )
    (tmp_path / "requirements.txt").write_text("boto3>=1\npsycopg[binary]>=3\nrequests>=2\nwebsockets>=12\n")
    return tmp_path


def node_project(tmp_path):
    (tmp_path / "api.js").write_text(
        """import pg from 'pg';
import axios from 'axios';
import { S3Client } from '@aws-sdk/client-s3';
import WebSocket from 'ws';
const s3 = new S3Client({});
"""
    )
    (tmp_path / "worker.js").write_text(
        """const pg = require('pg');
const { S3Client } = require('@aws-sdk/client-s3');
const s3 = new S3Client({});
"""
    )
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "scripts": {"start": "node api.js"},
                "dependencies": {
                    "@aws-sdk/client-s3": "^3.0.0",
                    "axios": "^1.0.0",
                    "pg": "^8.0.0",
                    "ws": "^8.0.0",
                },
            }
        )
    )
    return tmp_path


def setup(project, language):
    base = registration()
    registered = replace(
        base,
        scope=replace(base.scope, source_revision=source_digest(project)),
    )
    suffix = ".py" if language == "python" else ".js"
    source_registration = RegisteredStaticSourceInventory(
        registered,
        language,
        (("api", ("api" + suffix,)), ("jobs", ("worker" + suffix,))),
    )
    runtime = Mock()
    runtime.collect.side_effect = lambda value, endpoint: snapshot(value, endpoint)
    published = {}

    class Publisher:
        def publish(self, report):
            published[report["report_id"]] = report
            return report["report_id"]

    reader = StaticSourceWorkloadInventoryReader(
        source_registration,
        project,
        runtime,
        Publisher(),
        clock=lambda: NOW,
    )
    return reader, registered, runtime, published


@pytest.mark.parametrize(("factory", "language"), [(python_project, "python"), (node_project, "node")])
def test_bounded_source_analysis_adds_immutable_evidence_before_runtime(factory, language, tmp_path):
    reader, registered, runtime, published = setup(factory(tmp_path), language)
    result = reader.collect(registered, "source")
    assert len(result.evidence_refs) == 2
    source_ref = next(value for value in result.evidence_refs if value.startswith("WSI-"))
    report = published[source_ref]
    assert report["status"] == "verified" and not report["execution_authorized"]
    assert {item["component_ref"] for item in report["files"]} == {"api", "jobs"}
    assert report["source_revision"] == registered.scope.source_revision
    runtime.collect.assert_called_once_with(registered, "source")


@pytest.mark.parametrize("change", ["dynamic", "unexpected", "missing", "unassigned", "revision"])
def test_ambiguous_or_changed_python_source_never_reaches_runtime(change, tmp_path):
    project = python_project(tmp_path)
    reader, registered, runtime, published = setup(project, "python")
    if change == "dynamic":
        with (project / "api.py").open("a") as output:
            output.write("\nmodule = __import__(name)\n")
    elif change == "unexpected":
        with (project / "worker.py").open("a") as output:
            output.write("\nopen('/tmp/output', 'w')\n")
    elif change == "missing":
        text = (project / "api.py").read_text().replace("import requests\n", "")
        (project / "api.py").write_text(text)
    elif change == "unassigned":
        (project / "hidden.py").write_text("import requests\n")
    else:
        registered = replace(
            registered,
            scope=replace(registered.scope, source_revision="f" * 64),
        )
    expected_error = ValueError if change == "revision" else WorkloadInventoryUnavailable
    with pytest.raises(expected_error):
        reader.collect(registered, "source")
    runtime.collect.assert_not_called()
    if change == "revision":
        assert not published
    else:
        assert len(published) <= 1


def test_unknown_runtime_package_and_custom_dockerfile_fail_closed(tmp_path):
    project = node_project(tmp_path)
    package = json.loads((project / "package.json").read_text())
    package["dependencies"]["mystery-network-client"] = "1.0.0"
    (project / "package.json").write_text(json.dumps(package))
    reader, registered, runtime, _published = setup(project, "node")
    with pytest.raises(WorkloadInventoryUnavailable):
        reader.collect(registered, "target")
    runtime.collect.assert_not_called()
    (project / "Dockerfile").write_text("FROM node:22\n")
    reader, registered, runtime, _published = setup(project, "node")
    with pytest.raises(WorkloadInventoryUnavailable):
        reader.collect(registered, "target")
    runtime.collect.assert_not_called()


@pytest.mark.parametrize(("factory", "language"), [(python_project, "python"), (node_project, "node")])
def test_undeclared_or_unclassified_import_never_reaches_runtime(factory, language, tmp_path):
    project = factory(tmp_path)
    path = project / ("api.py" if language == "python" else "api.js")
    suffix = "\nimport mystery_client\n" if language == "python" else "\nrequire('mystery-client');\n"
    with path.open("a") as output:
        output.write(suffix)
    reader, registered, runtime, published = setup(project, language)
    with pytest.raises(WorkloadInventoryUnavailable):
        reader.collect(registered, "source")
    runtime.collect.assert_not_called()
    assert next(iter(published.values()))["status"] == "blocked"


def test_one_source_file_cannot_be_attributed_to_multiple_components(tmp_path):
    project = python_project(tmp_path)
    _reader, registered, _runtime, _published = setup(project, "python")
    with pytest.raises(ValueError, match="exactly one component"):
        RegisteredStaticSourceInventory(
            registered,
            "python",
            (("api", ("api.py",)), ("jobs", ("api.py", "worker.py"))),
        )


def test_rehashed_report_cannot_omit_registered_source_evidence(tmp_path):
    reader, registered, _runtime, published = setup(python_project(tmp_path), "python")
    result = reader.collect(registered, "source")
    report = published[next(value for value in result.evidence_refs if value.startswith("WSI-"))]
    report["files"] = report["files"][:-1]
    unsigned = {key: value for key, value in report.items() if key != "report_id"}
    report["report_id"] = (
        "WSI-"
        + hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
    )
    with pytest.raises(ValueError, match="Invalid static source"):
        validate_static_source_inventory_report(reader.registration, report)
