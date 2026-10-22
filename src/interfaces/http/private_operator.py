"""Explicit single-operator authentication for a loopback preparation API.

This is not public hosting authentication. Keep remote access inside an SSH/SSM
tunnel; never expose this HTTP listener through a reverse proxy or port publish.
"""

import base64
import binascii
import hmac
import json
import re

from domain.access import LoginSource, Principal, Role


class PrivateOperatorAuthenticator:
    challenge = 'Basic realm="Sky private operator", charset="UTF-8"'

    def __init__(self, *, password, user_id, organization_id, authority):
        if not isinstance(password, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", password):
            raise ValueError(
                "Private operator password must be a random URL-safe token of at least 32 characters"
            )
        if not re.fullmatch(r"127\.0\.0\.1:[0-9]{1,5}", authority):
            raise ValueError("Private operator requires an explicit loopback authority")
        self._credential = f"{user_id}:{password}".encode()
        self.authority = authority
        self.principal = Principal(user_id, organization_id, Role.DEPLOYER, LoginSource.PRIVATE_OPERATOR)

    @classmethod
    def from_json(cls, document, *, host, port, origin):
        if host != "127.0.0.1" or type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("Private operator API must listen on IPv4 loopback with a fixed port")
        authority = f"127.0.0.1:{port}"
        if origin != f"http://{authority}":
            raise ValueError("Private operator origin must match the loopback listener")

        def unique(pairs):
            result = dict(pairs)
            if len(result) != len(pairs):
                raise ValueError("Duplicate private operator setting")
            return result

        try:
            if not isinstance(document, str) or len(document) > 4096:
                raise ValueError()
            value = json.loads(document, object_pairs_hook=unique)
            if not isinstance(value, dict) or set(value) != {"password", "user_id", "organization_id"}:
                raise ValueError()
            return cls(**value, authority=authority)
        except (ValueError, TypeError):
            raise ValueError("Invalid private operator configuration") from None

    def authenticate_request(self, headers):
        # Reject duplicate framing/authentication headers and DNS rebinding hosts.
        def single(name):
            if hasattr(headers, "get_all"):
                values = headers.get_all(name)
                return values[0] if values is not None and len(values) == 1 else None
            return headers.get(name)

        if single("Host") != self.authority:
            return None
        authorization = single("Authorization")
        if not isinstance(authorization, str) or len(authorization) > 1024:
            return None
        scheme, separator, encoded = authorization.partition(" ")
        if not separator or scheme.lower() != "basic":
            return None
        try:
            supplied = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            return None
        return self.principal if hmac.compare_digest(supplied, self._credential) else None
