"""Pinned authenticated HTTPS read probe for the registered environment entrypoint."""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import socket
import ssl
from dataclasses import dataclass

from adapters.runtime.environment_secrets import ControlRuntimeSecretMaterial
from adapters.runtime.pinned_ca import pinned_ca_bundle
from adapters.runtime.pinned_https import pinned_https_endpoint
from adapters.runtime.private_network import pinned_private_address
from domain.database_transfer import RegisteredDatabaseTransfer


def _ca_bundle(path, expected):
    try:
        content, _digest = pinned_ca_bundle(path, expected)
    except ValueError:
        raise ValueError("Pinned entrypoint CA bundle required")
    try:
        return content.decode()
    except UnicodeError:  # pragma: no cover -- the shared reader already proves UTF-8
        raise ValueError("Pinned entrypoint CA bundle required") from None


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate entrypoint evidence field")
        result[key] = value
    return result


@dataclass(frozen=True)
class RegisteredHttpsEnvironmentEntrypointProbe:
    transfer: RegisteredDatabaseTransfer
    endpoint: str
    address: str
    ca_path: str
    ca_sha256: str
    response_timeout: int = 10

    def __post_init__(self):
        if not isinstance(self.transfer, RegisteredDatabaseTransfer):
            raise TypeError("Registered environment transfer required")
        try:
            pinned_private_address(self.address)
            pinned_https_endpoint(self.endpoint)
        except ValueError:
            raise ValueError("Pinned private HTTPS entrypoint required") from None
        if type(self.response_timeout) is not int or not 1 <= self.response_timeout <= 30:
            raise ValueError("Pinned private HTTPS entrypoint required")
        _ca_bundle(self.ca_path, self.ca_sha256)
        value = {
            "schema_version": 1,
            "profile": "registered_https_environment_entrypoint_probe_v1",
            "transfer": self.transfer.document(),
            "endpoint": self.endpoint,
            "address": self.address,
            "ca_sha256": self.ca_sha256,
            "response_timeout": self.response_timeout,
        }
        object.__setattr__(
            self,
            "reference",
            "EPR-"
            + hashlib.sha256(
                json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            ).hexdigest(),
        )

    def bind(self, material, *, guard):
        if not isinstance(material, ControlRuntimeSecretMaterial) or not callable(guard):
            raise TypeError("Typed entrypoint credential and current guard required")
        ca_bundle = _ca_bundle(self.ca_path, self.ca_sha256)
        try:
            context = ssl.create_default_context(cadata=ca_bundle)
        except ssl.SSLError:
            raise ValueError("Valid pinned entrypoint CA bundle required") from None
        if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
            raise ValueError("Entrypoint TLS must verify certificate and hostname")
        return _BoundHttpsEnvironmentEntrypointProbe(self, material.token, context, guard)


class _BoundHttpsEnvironmentEntrypointProbe:
    def __init__(self, registration, token, context, guard):
        self.registration, self._token = registration, token
        self.context, self.guard = context, guard
        self.reference = registration.reference

    def __call__(self):
        r = self.registration
        url, port = pinned_https_endpoint(r.endpoint)
        connection = http.client.HTTPSConnection(
            url.hostname,
            port,
            timeout=r.response_timeout,
        )
        try:
            self.guard()
            raw = socket.create_connection((r.address, port), timeout=r.response_timeout)
            try:
                connection.sock = self.context.wrap_socket(raw, server_hostname=url.hostname)
                connection.sock.settimeout(r.response_timeout)
            except BaseException:
                raw.close()
                raise
            connection.request(
                "GET",
                url.path,
                headers={
                    "Authorization": "Bearer " + self._token,
                    "Accept": "application/json",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
            body = response.read(4097)
            if response.status != 200 or content_type != "application/json" or len(body) > 4096:
                raise ValueError("Successful bounded JSON entrypoint response required")
            value = json.loads(body, object_pairs_hook=_unique)
            if (
                not isinstance(value, dict)
                or set(value) != {"binding_hash"}
                or not isinstance(value["binding_hash"], str)
                or not re.fullmatch(r"[a-f0-9]{64}", value["binding_hash"])
            ):
                raise ValueError("Exact entrypoint binding evidence required")
            self.guard()
            return value
        except Exception:  # noqa: BLE001 -- credential, network, and response details stay private
            raise RuntimeError("Registered HTTPS entrypoint evidence unavailable") from None
        finally:
            connection.close()
