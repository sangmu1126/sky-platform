"""Real PostgreSQL admission links, independent of worker-supplied checkpoints."""

from copy import deepcopy
from dataclasses import replace

import pytest

from adapters.state.build_approval import PostgresBuildApprovalReader
from domain.access import Role
from ports.remote_builds import BuildSettings, request_for
from tests.contract.test_deployment_approvals import artifact, counts, expire, principal
from tests.contract.test_deployment_approvals import database as database  # noqa: PLC0414 -- pytest fixture
from tests.contract.test_deployment_approvals import store as store  # noqa: PLC0414 -- pytest fixture


@pytest.fixture
def admitted(store):
    plan = {
        "target": "aws",
        "replicas": 1,
        "source_digest": artifact().source_digest,
        "dockerfile_source": "existing",
        "dockerfile": "Dockerfile",
    }
    approval = store.approve(principal(), artifact(), plan)
    result = store.submit(principal(), approval.id, "approved-build")
    record = store.operations.records.load_job(result.job_id).record
    settings = BuildSettings(
        "sangmu1126/sky-builder",
        "main",
        "a" * 40,
        "b" * 40,
        "sky-build-artifacts",
        "123456789012",
        "ap-northeast-2",
    )
    return PostgresBuildApprovalReader(store.operations, settings), record


def test_consumed_expired_approval_is_read_only_historical_evidence(store, database, admitted):
    reader, record = admitted
    expire(store, database, record["approval_id"])
    before = counts(store, database)
    expected = request_for(
        store.operations.get(record["operation_id"]), store.operations.workspace, reader.settings
    )
    assert reader.expected_request(principal(user="reviewer", role=Role.ADMIN), record) == expected
    assert counts(store, database) == before
    assert store.operations.records.load_job(record["id"]).record == record


def test_worker_checkpoint_cannot_supply_expected_inputs(store, admitted):
    reader, record = admitted
    op = store.operations.get(record["operation_id"])
    expected = request_for(op, store.operations.workspace, reader.settings)
    lease = store.operations.claim(op.id, op.attempt_id, "worker")
    assert store.operations.checkpoint(lease, {"request": {"source_digest": "f" * 64}})
    assert reader.expected_request(principal(role=Role.ADMIN), record) == expected


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_digest", "f" * 64),
        ("created_by", "mallory"),
        ("plan_digest", "e" * 64),
        ("id", "0" * 16),
        ("application_id", "foreign"),
        ("target", "local"),
    ],
)
def test_snapshot_mismatch_is_rejected(admitted, field, value):
    reader, record = admitted
    changed = deepcopy(record)
    changed[field] = value
    with pytest.raises(ValueError):
        reader.expected_request(principal(role=Role.ADMIN), changed)


@pytest.mark.parametrize("change", ["owner", "consumption", "operation", "command", "scope"])
def test_corrupted_authoritative_links_fail_closed(store, database, admitted, change):
    reader, record = admitted
    with database() as connection:
        if change == "owner":
            connection.execute(
                "UPDATE sky_state.application_owners SET organization_id='foreign' WHERE workspace=%s",
                (store.operations.workspace,),
            )
        elif change == "consumption":
            connection.execute(
                "UPDATE sky_state.deployment_approvals SET consumed_key=%s WHERE workspace=%s",
                ("d" * 64, store.operations.workspace),
            )
        elif change == "operation":
            connection.execute(
                "UPDATE sky_state.operations SET request_hash=%s WHERE workspace=%s",
                ("e" * 64, store.operations.workspace),
            )
        elif change == "command":
            connection.execute(
                "UPDATE sky_state.operations SET command=jsonb_set(command,'{created_by}', '\"mallory\"') WHERE workspace=%s",
                (store.operations.workspace,),
            )
        else:
            reader.settings = replace(reader.settings, account_id="222222222222")
    with pytest.raises(ValueError):
        reader.expected_request(principal(role=Role.ADMIN), record)


@pytest.mark.parametrize("actor", [principal(), principal(org="foreign", role=Role.ADMIN)])
def test_nonadmin_and_foreign_admin_cannot_read_approved_source(admitted, actor):
    reader, record = admitted
    with pytest.raises((PermissionError, FileNotFoundError)):
        reader.expected_request(actor, record)


def test_unconsumed_approval_cannot_substitute_for_admitted_approval(store, admitted):
    reader, record = admitted
    unused = store.approve(principal(), artifact(), record["plan"])
    with pytest.raises(FileNotFoundError):
        reader.expected_request(principal(role=Role.ADMIN), {**record, "approval_id": unused.id})


@pytest.fixture
def signed_incident(store, admitted):
    import base64
    import hashlib
    import json
    from datetime import UTC, datetime

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from application.incident_build_approval import IncidentBuildApprovalInspection
    from application.kms_build_signature import KmsBuildSigningIdentity, signing_payload
    from application.security_hold import SecurityHold
    from ports.remote_builds import canonical, digest
    from tests.unit.test_incident_runtime_inspection import fixture

    reader, record = admitted
    actor = principal(user="user1", role=Role.ADMIN)
    records = store.operations.records
    saved = records.load_job(record["id"])
    runtime = json.loads(json.dumps(fixture()[0]).replace("111111111111", "123456789012"))
    records.save_job(record["id"], {**record, "result": runtime}, expected_revision=saved.revision)
    now = datetime.now(UTC)
    SecurityHold(records).place(
        actor, record["id"], incident_id="INC-1", reason="untrusted_artifact", now=now.isoformat()
    )
    held = records.load_job(record["id"])
    request = reader.expected_request(actor, held.record)
    manifest = canonical(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:" + "e" * 64,
                "size": 2,
            },
            "layers": [],
        }
    ).decode()
    statement = {
        "protocol": "sky-build-input-binding-v1",
        "build_id": request["build_id"],
        "request_digest": digest(request),
        "source_zip_sha256": artifact().sha256,
        "source_zip_size": artifact().size,
        "source_digest": request["source_digest"],
        "plan_digest": request["plan_digest"],
        "image_digest": "sha256:" + hashlib.sha256(manifest.encode()).hexdigest(),
        "config_digest": "sha256:" + "e" * 64,
        "archive_digest": "f" * 64,
        "repository": request["repository"],
        "workflow_sha": request["workflow_sha"],
        "platform_code_sha": request["platform_code_sha"],
        "run_id": 123,
        "zip_and_source_digest_checked": True,
        "faithful_compilation_verified": False,
        "image_safety_verified": False,
        "recovery_authorized": False,
    }
    private = ec.generate_private_key(ec.SECP256R1())
    identity = KmsBuildSigningIdentity(
        "arn:aws:kms:ap-northeast-2:123456789012:key/12345678-1234-1234-1234-123456789abc",
        private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
    )
    payload = signing_payload(statement, identity, now=now)
    bundle = {
        "payload": payload,
        "signature": base64.b64encode(private.sign(canonical(payload), ec.ECDSA(hashes.SHA256()))).decode(),
    }
    service = IncidentBuildApprovalInspection(
        records, reader, identity, clock=lambda: now.isoformat(), revalidate=lambda: actor
    )
    from types import SimpleNamespace

    return SimpleNamespace(
        reader=reader,
        record=record,
        records=records,
        actor=actor,
        held=held,
        identity=identity,
        bundle=bundle,
        statement=statement,
        service=service,
        manifest=manifest,
    )


def test_full_read_only_incident_comparison_uses_postgres_and_real_signature(signed_incident):
    c = signed_incident
    receipt = c.service.inspect(
        c.actor,
        c.record["id"],
        incident_id="INC-1",
        expected_boundary=c.held.record["security_review_boundary"]["id"],
        expected_revision=c.held.revision,
        bundle=c.bundle,
        image_digest=c.statement["image_digest"],
        config_digest=c.statement["config_digest"],
        run_id=123,
    )
    assert receipt["signature_verified"] and receipt["consumed_deployment_approval_matched"]
    assert not receipt["current_approval_verified"] and not receipt["recovery_authorized"]
    assert c.records.load_job(c.record["id"]) == c.held
