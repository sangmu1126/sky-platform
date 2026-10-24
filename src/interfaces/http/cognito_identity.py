"""Cognito access-token verification independent of an ALB-signed identity header.

Only operator-configured issuer/client/scopes and memberships are trusted. A TLS
entry point remains mandatory; this verifier does not create login or TLS hosting.
"""

import re
import threading
import time
import urllib.request
from dataclasses import dataclass

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from domain.access import LoginSource
from interfaces.http.alb_identity import (
    Memberships,
    _decode,
    _NoRedirect,
    _parse_configuration,
    _unique_json,
)

_ISSUER = re.compile(
    r"https://cognito-idp\.([a-z]{2}-[a-z]+-[0-9])\.amazonaws\.com/([a-z]{2}-[a-z]+-[0-9])_[A-Za-z0-9]{1,64}\Z"
)
_KID = re.compile(r"[A-Za-z0-9_+/=-]{1,128}\Z")


@dataclass(frozen=True)
class CognitoSettings:
    issuer: str
    client_id: str
    required_scopes: tuple[str, ...]
    login_source = LoginSource.EXTERNAL_IDP

    def __post_init__(self):
        match = _ISSUER.fullmatch(self.issuer) if isinstance(self.issuer, str) else None
        if match is None or match[1] != match[2]:
            raise ValueError("Expected a regional Cognito user-pool issuer")
        if not isinstance(self.client_id, str) or not re.fullmatch(r"[A-Za-z0-9]{1,128}", self.client_id):
            raise ValueError("Invalid Cognito app client")
        if (
            not isinstance(self.required_scopes, tuple)
            or not 1 <= len(self.required_scopes) <= 8
            or len(set(self.required_scopes)) != len(self.required_scopes)
            or any(
                not isinstance(scope, str) or not re.fullmatch(r"[!-~]{1,128}", scope)
                for scope in self.required_scopes
            )
        ):
            raise ValueError("Explicit, bounded API scopes are required")


def fetch_jwks(issuer):
    # Revalidate even if called independently. No token-provided key URL or redirects.
    CognitoSettings(issuer, "validation", ("validation",))
    url = issuer + "/.well-known/jwks.json"
    with urllib.request.build_opener(_NoRedirect()).open(url, timeout=3) as response:
        payload = response.read(65_537)
    if len(payload) > 65_536:
        raise ValueError("Cognito key set exceeds its limit")
    return _unique_json(payload)


class CognitoRequestAuthenticator:
    def __init__(self, settings, memberships, *, jwks_loader=fetch_jwks, clock=time.monotonic):
        self.settings = settings
        self.memberships = memberships
        self.loader = jwks_loader
        self.clock = clock
        self._lock = threading.Lock()
        self._keys = {}
        self._expires = 0
        self._refresh_after = 0

    @classmethod
    def from_json(cls, settings_json, memberships_json):
        try:
            if not isinstance(settings_json, str) or not isinstance(memberships_json, str):
                raise TypeError()
            doc = _parse_configuration(settings_json.encode())
            if (
                set(doc) != {"version", "issuer", "client_id", "required_scopes"}
                or type(doc["version"]) is not int
                or doc["version"] != 1
                or not isinstance(doc["required_scopes"], list)
            ):
                raise ValueError()
            settings = CognitoSettings(doc["issuer"], doc["client_id"], tuple(doc["required_scopes"]))
            members = Memberships.from_document(_parse_configuration(memberships_json.encode()), (settings,))
            return cls(settings, members)
        except (ValueError, TypeError, KeyError, UnicodeError):
            raise ValueError("Invalid Cognito identity configuration") from None

    def _key(self, kid):
        with self._lock:
            now = self.clock()
            if now < self._expires and kid in self._keys:
                return self._keys[kid]
            if now < self._refresh_after:
                raise ValueError("Signing key unavailable")
            # Bound unknown-kid traffic and failed refreshes to one fetch/minute/process.
            self._refresh_after = now + 60
            document = self.loader(self.settings.issuer)
            if (
                not isinstance(document, dict)
                or set(document) != {"keys"}
                or not isinstance(document["keys"], list)
                or not 1 <= len(document["keys"]) <= 8
            ):
                raise ValueError("Invalid signing key set")
            keys = {}
            for item in document["keys"]:
                if (
                    not isinstance(item, dict)
                    or item.get("kty") != "RSA"
                    or item.get("alg") != "RS256"
                    or item.get("use") != "sig"
                    or not isinstance(item.get("kid"), str)
                    or not _KID.fullmatch(item["kid"])
                    or item["kid"] in keys
                    or "d" in item
                ):
                    raise ValueError("Invalid signing key")
                key = jwt.PyJWK.from_dict(item, algorithm="RS256").key
                if not isinstance(key, rsa.RSAPublicKey) or not 2048 <= key.key_size <= 4096:
                    raise ValueError("Unexpected signing key size")
                keys[item["kid"]] = key
            self._keys, self._expires = keys, now + 300
            return keys[kid]

    def authenticate_request(self, headers):
        values = (
            headers.get_all("Authorization")
            if callable(getattr(headers, "get_all", None))
            else [headers.get("Authorization")]
        )
        if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], str):
            return None
        scheme, _, token = values[0].partition(" ")
        if scheme.lower() != "bearer" or not 1 <= len(token) <= 16_384:
            return None
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            header, unverified = _unique_json(_decode(parts[0])), _unique_json(_decode(parts[1]))
            if (
                header.get("alg") != "RS256"
                or any(k in header for k in ("crit", "jku", "x5u", "jwk"))
                or not isinstance(header.get("kid"), str)
                or not _KID.fullmatch(header["kid"])
            ):
                return None
            # Reject wrong contexts before any network fetch. These claims are NOT trusted yet.
            if (
                unverified.get("iss") != self.settings.issuer
                or unverified.get("client_id") != self.settings.client_id
                or unverified.get("token_use") != "access"
            ):
                return None
            if (
                type(unverified.get("exp")) is not int
                or type(unverified.get("iat")) is not int
                or ("nbf" in unverified and type(unverified["nbf"]) is not int)
            ):
                return None
            claims = jwt.decode(
                token,
                self._key(header["kid"]),
                algorithms=["RS256"],
                issuer=self.settings.issuer,
                options={
                    "require": ["exp", "iat", "iss", "sub", "client_id", "token_use", "scope"],
                    "verify_aud": False,
                },
            )
            # Cognito access tokens bind to client_id, not the ID-token aud field.
            if (
                claims["exp"] <= claims["iat"]
                or not isinstance(claims["scope"], str)
                or not set(self.settings.required_scopes) <= set(claims["scope"].split())
            ):
                return None
            if not isinstance(claims["sub"], str) or not 1 <= len(claims["sub"]) <= 256:
                return None
            return self.memberships.resolve(self.settings.issuer, claims["sub"], LoginSource.EXTERNAL_IDP)
        except (ValueError, TypeError, KeyError, UnicodeError, OSError, jwt.PyJWTError):
            return None
