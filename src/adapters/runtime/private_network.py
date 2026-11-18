"""Canonical private addresses permitted for registered environment transports."""

from __future__ import annotations

import ipaddress

_IPV4_PRIVATE = tuple(
    ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_IPV6_PRIVATE = ipaddress.ip_network("fc00::/7")


def pinned_private_address(value):
    try:
        if not isinstance(value, str) or "%" in value:
            raise ValueError
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("Canonical pinned private address required") from None
    if value != str(address):
        raise ValueError("Canonical pinned private address required")
    allowed = address.is_loopback or (
        address.version == 4 and any(address in network for network in _IPV4_PRIVATE)
    )
    if address.version == 6:
        allowed = address.is_loopback or address in _IPV6_PRIVATE
    if not allowed or getattr(address, "ipv4_mapped", None) is not None:
        raise ValueError("Canonical pinned private address required")
    return address
