"""Canonical DNS HTTPS endpoints for registered environment transports."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

_HOST = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_SEGMENT = re.compile(r"[A-Za-z0-9_~-](?:[A-Za-z0-9._~-]{0,254}[A-Za-z0-9_~-])?\Z")


def pinned_dns_hostname(value):
    if not isinstance(value, str) or not _HOST.fullmatch(value):
        raise ValueError("Canonical pinned DNS hostname required")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("Canonical pinned DNS hostname required")


def pinned_https_endpoint(value):
    if not isinstance(value, str) or not value.startswith("https://") or len(value.encode()) > 2048:
        raise ValueError("Canonical pinned HTTPS endpoint required")
    try:
        url = urlsplit(value)
        port = url.port or 443
        hostname = pinned_dns_hostname(url.hostname)
    except ValueError:
        raise ValueError("Canonical pinned HTTPS endpoint required") from None
    expected_authority = url.hostname if url.port is None else f"{url.hostname}:{port}"
    segments = url.path[1:].split("/") if url.path != "/" else []
    if (
        url.scheme != "https"
        or hostname != url.hostname
        or url.netloc != expected_authority
        or value != f"https://{expected_authority}{url.path}"
        or url.username
        or url.password
        or url.query
        or url.fragment
        or type(port) is not int
        or not 1 <= port <= 65535
        or not url.path.startswith("/")
        or len(url.path.encode()) > 1024
        or any(segment in {"", ".", ".."} or not _SEGMENT.fullmatch(segment) for segment in segments)
    ):
        raise ValueError("Canonical pinned HTTPS endpoint required")
    return url, port
