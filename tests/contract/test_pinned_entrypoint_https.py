"""Actual pinned-address TLS and authenticated entrypoint binding evidence."""

import hashlib
import json
import socket
import ssl
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from unittest.mock import Mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from adapters.database.pinned_entrypoint_https import RegisteredHttpsEnvironmentEntrypointProbe
from adapters.runtime.environment_secrets import ControlRuntimeSecretMaterial
from tests.unit.test_database_transfer import transfer

HOST = "gateway.rehearsal.test"
PATH = "/api/scoreboard"
BINDING = "a" * 64


def tls_files(tmp_path):
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Sky entrypoint test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    ca_path, cert_path, key_path = tmp_path / "ca.pem", tmp_path / "server.pem", tmp_path / "key.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    ca_path.chmod(0o644)
    key_path.chmod(0o600)
    return ca_path, cert_path, key_path


@pytest.fixture
def https_entrypoint(tmp_path):
    ca, certificate, key = tls_files(tmp_path)
    token = "isolated-entrypoint-token"
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            authorized = self.headers.get("Authorization") == "Bearer " + token
            calls.append((self.path, authorized, self.headers.get("Host")))
            if self.path != PATH or not authorized:
                self.send_response(401)
                self.end_headers()
                return
            body = json.dumps({"binding_hash": BINDING}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield ca, server.server_port, token, calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def registration(ca, port, host=HOST):
    return RegisteredHttpsEnvironmentEntrypointProbe(
        transfer(),
        f"https://{host}:{port}{PATH}",
        "127.0.0.1",
        str(ca),
        hashlib.sha256(ca.read_bytes()).hexdigest(),
        response_timeout=5,
    )


def test_actual_pinned_tls_probe_uses_registered_address_sni_and_credential(https_entrypoint):
    ca, port, token, calls = https_entrypoint
    context = ssl.create_default_context(cadata=ca.read_text())
    with (
        socket.create_connection(("127.0.0.1", port), timeout=5) as raw,
        context.wrap_socket(raw, server_hostname=HOST) as tls,
    ):
        assert tls.version() in {"TLSv1.2", "TLSv1.3"}
    guard = Mock()
    probe = registration(ca, port).bind(ControlRuntimeSecretMaterial(token), guard=guard)
    assert probe() == {"binding_hash": BINDING}
    assert calls == [(PATH, True, f"{HOST}:{port}")]
    assert guard.call_count == 2


def test_actual_tls_probe_rejects_wrong_credential_and_hostname_without_retry(https_entrypoint):
    ca, port, _token, calls = https_entrypoint
    probe = registration(ca, port).bind(ControlRuntimeSecretMaterial("wrong-token"), guard=Mock())
    with pytest.raises(RuntimeError, match="entrypoint evidence unavailable"):
        probe()
    assert calls == [(PATH, False, f"{HOST}:{port}")]

    wrong_host = registration(ca, port, host="wrong.rehearsal.test").bind(
        ControlRuntimeSecretMaterial("wrong-token"), guard=Mock()
    )
    with pytest.raises(RuntimeError, match="entrypoint evidence unavailable"):
        wrong_host()
    assert len(calls) == 1
