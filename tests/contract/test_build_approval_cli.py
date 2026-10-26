"""Installed CLI composition with actual PostgreSQL and local ECDSA signatures."""

import base64
import json
import os
from dataclasses import asdict
from unittest.mock import patch

import pytest

from application.security_hold import SecurityHold
from interfaces.b_runtime import main
from ports.remote_builds import canonical
from tests.contract.test_build_approval import admitted as admitted  # noqa: PLC0414
from tests.contract.test_build_approval import signed_incident as signed_incident  # noqa: PLC0414
from tests.contract.test_deployment_approvals import database as database  # noqa: PLC0414
from tests.contract.test_deployment_approvals import store as store  # noqa: PLC0414
from tests.unit.test_kms_build_key import native
from tests.unit.test_security_hold_cli import configured_cli as configured_cli  # noqa: PLC0414


@pytest.mark.parametrize(
    "change",
    [
        None,
        "signature",
        "revision",
        "run",
        "ledger",
        "final-status",
        "key-disabled",
        "key-pending",
        "key-denied",
    ],
)
def test_cli_reads_authoritative_state_without_releasing_or_mutating(
    configured_cli, signed_incident, store, database, tmp_path, monkeypatch, capsys, change
):
    import psycopg

    c = signed_incident
    monkeypatch.setenv("SKY_STATE_WORKSPACE", store.operations.workspace)
    memberships = json.loads(os.environ["SKY_MEMBERSHIPS_JSON"])
    memberships["members"][0]["organization_id"] = c.actor.organization_id
    monkeypatch.setenv("SKY_MEMBERSHIPS_JSON", json.dumps(memberships))
    (tmp_path / "key.json").write_bytes(
        canonical(
            {
                "version": 1,
                "key_arn": c.identity.key_arn,
                "public_key_der": base64.b64encode(c.identity.public_key_der).decode(),
            }
        )
    )
    if change == "signature":
        c.bundle["payload"]["statement"]["source_digest"] = "d" * 64
    (tmp_path / "bundle.json").write_bytes(canonical(c.bundle))
    registration = tmp_path / "inspection.json"
    registration.write_bytes(
        canonical(
            {
                "version": 1,
                "key_config": "key.json",
                "builder": asdict(c.reader.settings),
                "bundle": "bundle.json",
                "image_digest": c.statement["image_digest"],
                "config_digest": c.statement["config_digest"],
                "run_id": 124 if change == "run" else 123,
            }
        )
    )
    if change == "ledger":
        with database() as db:
            db.execute(
                "UPDATE sky_state.deployment_approvals SET consumed_key=%s WHERE workspace=%s",
                ("e" * 64, store.operations.workspace),
            )
    args = [
        "security-hold",
        "inspect-build-approval",
        "--job-id",
        c.record["id"],
        "--user-id",
        c.actor.user_id,
        "--organization-id",
        c.actor.organization_id,
        "--incident-id",
        "INC-1",
        "--expected-boundary",
        c.held.record["security_review_boundary"]["id"],
        "--expected-revision",
        str(c.held.revision + (change == "revision")),
        "--build-approval-config",
        str(registration),
    ]
    original_status = SecurityHold.status
    observed = []

    def status(service, *args):
        with service.writer.records.connection_factory() as db:
            assert db.execute("SHOW transaction_read_only").fetchone()[0] == "on"
            with pytest.raises(psycopg.errors.ReadOnlySqlTransaction), db.transaction():
                db.execute("UPDATE sky_state.metadata_records SET revision=revision WHERE false")
        observed.append(True)
        result = original_status(service, *args)
        if change == "final-status":
            result["metadata_revision"] += 1
        return result

    from datetime import UTC, datetime

    _, session, kms, _ = native(c.identity, clock=lambda: datetime.now(UTC))
    if change in {"key-disabled", "key-pending"}:
        kms.describe_key.return_value["KeyMetadata"].update(
            KeyState="Disabled" if change == "key-disabled" else "PendingDeletion", Enabled=False
        )
    elif change == "key-denied":
        from botocore.exceptions import ClientError

        kms.describe_key.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "private-diagnostic"}}, "DescribeKey"
        )
    with (
        patch("interfaces.security_hold.RotatingDatabaseConnection", return_value=database),
        patch("boto3.client", side_effect=AssertionError("No AWS API needed")),
        patch("boto3.Session", return_value=session),
        patch.object(SecurityHold, "status", status),
    ):
        if change is not None:
            with pytest.raises(SystemExit) as exc:
                main(args)
            assert exc.value.code == 1
            assert capsys.readouterr().out == ""
        else:
            main(args)
            result = json.loads(capsys.readouterr().out)
            assert observed
            assert result["status"] == "held" and result["observed_only"]
            receipt = result["build_approval"]
            assert receipt["signature_verified"] and receipt["consumed_deployment_approval_matched"]
            assert receipt["read_only"] and not receipt["recovery_authorized"]
            assert not receipt["current_approval_verified"] and receipt["key_liveness_checked"]
            assert receipt["signing_key"]["key_state"] == "Enabled"
            assert kms.describe_key.call_count == 2
            for private in ("approved_plan_json", "public_key_der", "signature", "source_ref"):
                assert f'"{private}":' not in json.dumps(result)
    assert c.records.load_job(c.record["id"]) == c.held
