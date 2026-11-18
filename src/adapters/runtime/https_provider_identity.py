"""Pinned HTTPS service identity inspection using CA trust and leaf SPKI."""

import hashlib
import json
import os
import re
import socket
import ssl
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from adapters.runtime.provider_identity import (
    ObservedProviderResourceIdentity,
    RegisteredProviderResourceIdentity,
)
from domain.environment_transition import _digest, _ref


def _ca_bundle(path):
    value = Path(path)
    if not value.is_absolute() or value.is_symlink():
        raise ValueError("Absolute plain CA bundle required")
    descriptor = os.open(value, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & 0o022
            or not 1 <= metadata.st_size <= 1024 * 1024
        ):
            raise ValueError("Immutable bounded CA bundle required")
        data = os.read(descriptor, metadata.st_size + 1)
        if len(data) != metadata.st_size:
            raise ValueError("CA bundle changed while reading")
        text = data.decode()
        if "-----BEGIN CERTIFICATE-----" not in text:
            raise ValueError("PEM CA bundle required")
        return data, hashlib.sha256(data).hexdigest()
    finally:
        os.close(descriptor)


def https_provider_identity_authority_ref(ca_bundle, trust_profile_ref):
    _ref(trust_profile_ref)
    _data, digest = _ca_bundle(ca_bundle)
    value = hashlib.sha256(
        json.dumps(
            {
                "profile": "https-spki-provider-identity-v1",
                "trust_profile_ref": trust_profile_ref,
                "ca_bundle_sha256": digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return "https-" + value


def _host(value):
    if (
        not isinstance(value, str)
        or value != value.lower()
        or len(value) > 253
        or value.encode("idna").decode() != value
        or not re.fullmatch(
            r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
            value,
        )
    ):
        raise ValueError("Canonical HTTPS service host required")


def https_resource_identity_sha256(*, host, port, spki_sha256):
    _host(host)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Canonical HTTPS service port required")
    _digest(spki_sha256)
    return hashlib.sha256(
        json.dumps(
            {
                "provider": "https",
                "resource_kind": "https-service",
                "host": host,
                "port": port,
                "spki_sha256": spki_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


@dataclass(frozen=True)
class RegisteredHttpsProviderIdentityTarget:
    resource_ref: str
    host: str
    port: int
    spki_sha256: str

    def __post_init__(self):
        _ref(self.resource_ref)
        _host(self.host)
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("Canonical HTTPS service port required")
        _digest(self.spki_sha256)


def _tls_leaf_certificate(context, host, port, timeout):
    with (
        socket.create_connection((host, port), timeout=timeout) as raw,
        context.wrap_socket(raw, server_hostname=host) as connection,
    ):
        certificate = connection.getpeercert(binary_form=True)
    if not isinstance(certificate, bytes) or not 1 <= len(certificate) <= 256 * 1024:
        raise ValueError("Bounded HTTPS leaf certificate required")
    return certificate


def _spki_sha256(certificate):
    leaf = x509.load_der_x509_certificate(certificate)
    public_key = leaf.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(public_key).hexdigest()


class PinnedHttpsProviderIdentityInspector:
    def __init__(
        self,
        *,
        authority_ref,
        trust_profile_ref,
        ca_bundle,
        targets,
        clock,
        connector=_tls_leaf_certificate,
        timeout_seconds=5,
    ):
        data, digest = _ca_bundle(ca_bundle)
        if authority_ref != https_provider_identity_authority_ref(ca_bundle, trust_profile_ref):
            raise ValueError("HTTPS provider authority registration changed")
        if (
            not isinstance(targets, tuple)
            or not 1 <= len(targets) <= 128
            or not all(isinstance(value, RegisteredHttpsProviderIdentityTarget) for value in targets)
            or tuple(sorted(targets, key=lambda value: value.resource_ref)) != targets
            or len({value.resource_ref for value in targets}) != len(targets)
        ):
            raise ValueError("Canonical registered HTTPS provider targets required")
        if not callable(clock) or not callable(connector):
            raise TypeError("HTTPS provider connector and clock required")
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 20:
            raise ValueError("Bounded HTTPS provider timeout required")
        try:
            context = ssl.create_default_context(cadata=data.decode())
        except (UnicodeError, ssl.SSLError):
            raise ValueError("Valid HTTPS CA trust bundle required") from None
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        self.authority_ref = authority_ref
        self.ca_bundle = Path(ca_bundle)
        self.ca_bundle_sha256 = digest
        self.targets = {value.resource_ref: value for value in targets}
        self.clock = clock
        self.connector = connector
        self.timeout_seconds = timeout_seconds
        self.context = context

    def inspect(self, resource):
        if not isinstance(resource, RegisteredProviderResourceIdentity):
            raise TypeError("Registered provider resource identity required")
        if resource.provider_ref != "https" or resource.resource_kind != "https-service":
            raise ValueError("HTTPS inspector requires an HTTPS service resource")
        target = self.targets.get(resource.resource_ref)
        if target is None:
            raise ValueError("Registered HTTPS provider target changed")
        try:
            if _ca_bundle(self.ca_bundle)[1] != self.ca_bundle_sha256:
                raise ValueError("HTTPS CA trust bundle changed")
            certificate = self.connector(
                self.context,
                target.host,
                target.port,
                self.timeout_seconds,
            )
            spki = _spki_sha256(certificate)
            if spki != target.spki_sha256 or _ca_bundle(self.ca_bundle)[1] != self.ca_bundle_sha256:
                raise ValueError("HTTPS service identity changed")
            digest = https_resource_identity_sha256(
                host=target.host,
                port=target.port,
                spki_sha256=spki,
            )
            return ObservedProviderResourceIdentity(
                resource.logical_ref,
                "https",
                "https-service",
                target.resource_ref,
                digest,
                self.authority_ref,
                self.clock(),
            )
        except Exception:  # noqa: BLE001 -- network and certificate diagnostics remain private
            raise OSError("Registered HTTPS provider identity unavailable") from None
