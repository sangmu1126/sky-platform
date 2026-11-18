"""No-retry private HTTPS control transport with operator-pinned network address.

The caller must audit the owning ECS task/service before each command. Address
pinning does not replace certificate/hostname verification or execution leases.
The TLS identity remains the registered DNS name even when a task IP is used.
"""

import http.client
import json
import re
import socket
import ssl
from urllib.parse import urlsplit

from adapters.runtime.private_network import pinned_private_address


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate control receipt field")
        result[key] = value
    return result


def _constant(_value):
    raise ValueError("Non-finite control receipt value")


class PinnedHTTPSControlTransport:
    def __init__(self, endpoint, token, *, address, ssl_context, guard, response_timeout=30):
        url = urlsplit(endpoint)
        try:
            ip = pinned_private_address(address)
            port = url.port or 443
        except ValueError:
            raise ValueError(
                "Registered private address, TLS identity and control credential required"
            ) from None
        if (
            url.scheme != "https"
            or not url.hostname
            or not url.path
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", url.hostname)
            or not re.fullmatch(r"/[A-Za-z0-9._~/%-]{0,1023}", url.path)
            or url.username
            or url.password
            or url.query
            or url.fragment
            or not isinstance(token, str)
            or not 1 <= len(token.encode()) <= 4096
            or "\r" in token
            or "\n" in token
            or getattr(ssl_context, "verify_mode", None) != ssl.CERT_REQUIRED
            or not getattr(ssl_context, "check_hostname", False)
            or not callable(guard)
            or type(response_timeout) is not int
            or not 1 <= response_timeout <= 60
        ):
            raise ValueError("Registered private address, TLS identity and control credential required")
        self.url, self.address, self._token = url, str(ip), token
        self.port = port
        self.context, self.guard = ssl_context, guard
        self.response_timeout = response_timeout

    def __call__(self, command):
        self.guard()
        connection = http.client.HTTPSConnection(self.url.hostname, self.port, timeout=self.response_timeout)
        try:
            raw = socket.create_connection((self.address, self.port), timeout=self.response_timeout)
            try:
                connection.sock = self.context.wrap_socket(raw, server_hostname=self.url.hostname)
                connection.sock.settimeout(self.response_timeout)
            except BaseException:
                raw.close()
                raise
            body = json.dumps(command, separators=(",", ":"), allow_nan=False).encode()
            if len(body) > 16384:
                raise ValueError("Bounded control command required")
            connection.request(
                "POST",
                self.url.path or "/",
                body=body,
                headers={
                    "Authorization": "Bearer " + self._token,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
            if response.status != 200 or content_type != "application/json":
                raise ValueError("Successful non-redirecting control response required")
            result = response.read(16385)
            if len(result) > 16384:
                raise ValueError("Bounded control receipt required")
            result = json.loads(result, object_pairs_hook=_unique, parse_constant=_constant)
            self.guard()
            return result
        except Exception:  # noqa: BLE001 -- never expose tokens or replay a control mutation
            raise RuntimeError("Private HTTPS control outcome requires reconciliation") from None
        finally:
            connection.close()
