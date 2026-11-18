"""Environment transports accept only canonical loopback, RFC1918, or IPv6 ULA addresses."""

import pytest

from adapters.runtime.private_network import pinned_private_address


@pytest.mark.parametrize(
    "value",
    ["127.0.0.1", "::1", "10.0.0.1", "172.16.0.1", "172.31.255.254", "192.168.1.1", "fd00::1"],
)
def test_registered_private_transport_address_is_exact_and_canonical(value):
    assert str(pinned_private_address(value)) == value


@pytest.mark.parametrize(
    "value",
    [
        "8.8.8.8",
        "169.254.169.254",
        "100.64.0.1",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "0.0.0.0",
        "fe80::1",
        "2001:db8::1",
        "::ffff:127.0.0.1",
        "FD00::1",
        "fd00::1%en0",
        "hostname.internal",
        None,
    ],
)
def test_link_local_reserved_documentation_public_and_noncanonical_addresses_are_rejected(value):
    with pytest.raises(ValueError, match="Canonical pinned private address"):
        pinned_private_address(value)
