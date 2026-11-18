"""Pinned authenticated HTTPS read probe for the registered environment entrypoint."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import socket
import ssl
import stat
from dataclasses import dataclass
from pathlib import Path

from adapters.runtime.environment_secrets import ControlRuntimeSecretMaterial
from adapters.runtime.pinned_https import pinned_https_endpoint
from adapters.runtime.private_network import pinned_private_address
from domain.database_transfer import RegisteredDatabaseTransfer


def _ca_bundle(path, expected):
    value = Path(path)
    if (
        not isinstance(expected, str)
        or not re.fullmatch(r"[a-f0-9]{64}", expected)
        or not value.is_absolute()
    ):
        raise ValueError("Pinned entrypoint CA bundle required")
    descriptor = os.open(value, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 1 <= before.st_size <= 1024 * 1024
        ):
            raise ValueError("Pinned entrypoint CA bundle required")
        content = bytearray()
        while len(content) <= 1024 * 1024:
            chunk = os.read(descriptor, min(65536, 1024 * 1024 + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        if (
            len(content) != before.st_size
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or hashlib.sha256(content).hexdigest() != expected
        ):
            raise ValueError("Pinned entrypoint CA bundle required")
        try:
            text = bytes(content).decode()
        except UnicodeError:
            raise ValueError("Pinned entrypoint CA bundle required") from None
        if "-----BEGIN CERTIFICATE-----" not in text:
            raise ValueError("Pinned entrypoint CA bundle required")
        return text
    finally:
        os.close(descriptor)


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
