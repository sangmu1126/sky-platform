"""Public, non-secret configuration for a Cognito authorization-code/PKCE browser."""

import re
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class CognitoBrowser:
    domain: str
    origin: str
    identity: object

    def __post_init__(self):
        region = urlsplit(self.identity.issuer).hostname.split(".")[1]
        if not isinstance(self.domain, str) or not re.fullmatch(
            rf"https://[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.auth\.{re.escape(region)}\.amazoncognito\.com",
            self.domain,
        ):
            raise ValueError("Expected the configured region's Cognito managed login domain")
        url = urlsplit(self.origin)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or self.origin != f"https://{url.netloc}"
            or url.port == 0
        ):
            raise ValueError("Browser login requires the exact HTTPS application origin")

    def public_config(self):
        return {
            "origin": self.origin,
            "client_id": self.identity.client_id,
            "authorization_endpoint": self.domain + "/oauth2/authorize",
            "token_endpoint": self.domain + "/oauth2/token",
            "logout_endpoint": self.domain + "/logout",
            "redirect_uri": self.origin + "/auth/callback",
            "logout_uri": self.origin + "/login",
            "scopes": sorted({"openid", *self.identity.required_scopes}),
        }
