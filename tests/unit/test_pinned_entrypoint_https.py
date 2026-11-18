"""Entrypoint evidence uses one pinned authenticated HTTPS read without retries."""

import hashlib
import json
import ssl
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from adapters.database.pinned_entrypoint_https import RegisteredHttpsEnvironmentEntrypointProbe
from adapters.runtime.environment_secrets import ControlRuntimeSecretMaterial
from tests.unit.test_database_transfer import transfer


def fixture(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\npublic-ca\n-----END CERTIFICATE-----\n")
    registration = RegisteredHttpsEnvironmentEntrypointProbe(
        transfer(),
        "https://gateway.rehearsal.test:8443/api/scoreboard",
        "127.0.0.1",
        str(ca),
        hashlib.sha256(ca.read_bytes()).hexdigest(),
    )
    context = Mock(verify_mode=ssl.CERT_REQUIRED, check_hostname=True)
    wrapped = Mock()
    context.wrap_socket.return_value = wrapped
    raw = Mock()
    response = Mock(
        status=200,
        getheader=Mock(return_value="application/json; charset=utf-8"),
        read=Mock(return_value=json.dumps({"binding_hash": "a" * 64}).encode()),
    )
    connection = Mock(getresponse=Mock(return_value=response))
    return registration, context, raw, wrapped, response, connection


def test_bound_probe_reads_exact_binding_hash_over_pinned_tls(tmp_path):
    registration, context, raw, _wrapped, _response, connection = fixture(tmp_path)
    guard = Mock()
    material = ControlRuntimeSecretMaterial("private-entrypoint-token")
    with (
        patch(
            "adapters.database.pinned_entrypoint_https.ssl.create_default_context",
            return_value=context,
        ),
        patch(
            "adapters.database.pinned_entrypoint_https.socket.create_connection",
            return_value=raw,
        ) as create,
        patch(
            "adapters.database.pinned_entrypoint_https.http.client.HTTPSConnection",
            return_value=connection,
        ),
    ):
        probe = registration.bind(material, guard=guard)
        assert probe() == {"binding_hash": "a" * 64}
    assert probe.reference == registration.reference
    create.assert_called_once_with(("127.0.0.1", 8443), timeout=10)
    context.wrap_socket.assert_called_once_with(raw, server_hostname="gateway.rehearsal.test")
    connection.request.assert_called_once_with(
        "GET",
        "/api/scoreboard",
        headers={
            "Authorization": "Bearer private-entrypoint-token",
            "Accept": "application/json",
            "Connection": "close",
        },
    )
    assert guard.call_count == 2
    connection.close.assert_called_once_with()
    assert "private-entrypoint-token" not in repr(probe)


@pytest.mark.parametrize(
    "change",
    ["status", "redirect", "content", "oversize", "body", "duplicate", "network"],
)
def test_probe_failure_is_sanitized_and_never_retried(tmp_path, change):
    registration, context, raw, _wrapped, response, connection = fixture(tmp_path)
    if change == "status":
        response.status = 503
    elif change == "redirect":
        response.status = 302
    elif change == "content":
        response.getheader.return_value = "text/html"
    elif change == "oversize":
        response.read.return_value = b"x" * 4097
    elif change == "body":
        response.read.return_value = b'{"binding_hash":"changed"}'
    elif change == "duplicate":
        response.read.return_value = (
            b'{"binding_hash":"' + b"a" * 64 + b'","binding_hash":"' + b"b" * 64 + b'"}'
        )
    with (
        patch(
            "adapters.database.pinned_entrypoint_https.ssl.create_default_context",
            return_value=context,
        ),
        patch(
            "adapters.database.pinned_entrypoint_https.socket.create_connection",
            side_effect=OSError("private-network-detail") if change == "network" else None,
            return_value=raw,
        ) as create,
        patch(
            "adapters.database.pinned_entrypoint_https.http.client.HTTPSConnection",
            return_value=connection,
        ),
    ):
        probe = registration.bind(ControlRuntimeSecretMaterial("private-token"), guard=Mock())
        with pytest.raises(RuntimeError, match="entrypoint evidence unavailable") as error:
            probe()
    assert "private" not in str(error.value)
    assert create.call_count == 1
    connection.close.assert_called_once_with()


def test_probe_reference_excludes_ca_path_but_binds_digest_endpoint_and_transfer(tmp_path):
    registration, _context, _raw, _wrapped, _response, _connection = fixture(tmp_path)
    moved = tmp_path / "moved.pem"
    moved.write_bytes((tmp_path / "ca.pem").read_bytes())
    same = replace(registration, ca_path=str(moved))
    changed = replace(
        registration,
        endpoint="https://gateway.rehearsal.test:9443/api/scoreboard",
    )
    assert same.reference == registration.reference
    assert changed.reference != registration.reference
    assert str(tmp_path) not in registration.reference


def test_probe_rejects_public_transport_unverified_tls_or_changed_ca(tmp_path):
    registration, context, _raw, _wrapped, _response, _connection = fixture(tmp_path)
    with pytest.raises(ValueError, match="private HTTPS"):
        replace(registration, address="8.8.8.8")
    context.check_hostname = False
    with (
        patch(
            "adapters.database.pinned_entrypoint_https.ssl.create_default_context",
            return_value=context,
        ),
        pytest.raises(ValueError, match="verify"),
    ):
        registration.bind(ControlRuntimeSecretMaterial("token"), guard=Mock())
    with open(registration.ca_path, "a") as value:
        value.write("changed")
    with pytest.raises(ValueError, match="CA bundle"):
        registration.bind(ControlRuntimeSecretMaterial("token"), guard=Mock())


def test_probe_rejects_writable_ca_bundle(tmp_path):
    registration, _context, _raw, _wrapped, _response, _connection = fixture(tmp_path)
    Path(registration.ca_path).chmod(0o666)
    with pytest.raises(ValueError, match="CA bundle"):
        replace(registration)
