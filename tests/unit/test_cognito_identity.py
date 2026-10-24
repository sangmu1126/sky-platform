"""Signed access-token and real HTTP-boundary checks; no live Cognito calls."""

import base64
import json
import threading
import time
from argparse import Namespace
from email.message import Message
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from unittest.mock import Mock, patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from domain.access import LoginSource, Principal, Role
from interfaces.b_preparation_runtime import preparation_identity
from interfaces.b_runtime import main
from interfaces.http.alb_identity import Memberships
from interfaces.http.cognito_identity import CognitoRequestAuthenticator, CognitoSettings, fetch_jwks
from interfaces.http.deployment_preparation import DatabasePreparationApp, handler_for_preparation

ISSUER = "https://cognito-idp.ap-northeast-2.amazonaws.com/ap-northeast-2_TestPool"
CLIENT = "personalclient123"
SCOPE = "sky/deploy"
KID = "public/key+1="


@pytest.fixture
def verifier():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = {
        **jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True),
        "kid": KID,
        "use": "sig",
        "alg": "RS256",
    }
    loader = Mock(return_value={"keys": [jwk]})
    now = [1000]
    auth = CognitoRequestAuthenticator(
        CognitoSettings(ISSUER, CLIENT, (SCOPE,)),
        Memberships({(ISSUER, "subject-1"): ("alice", "personal", Role.DEPLOYER)}),
        jwks_loader=loader,
        clock=lambda: now[0],
    )
    return auth, key, loader, now


def token(key, **changes):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": "subject-1",
        "client_id": CLIENT,
        "token_use": "access",
        "iat": now - 10,
        "exp": now + 600,
        "scope": SCOPE,
        **changes,
    }
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": KID})


def request(value):
    h = Message()
    h["Authorization"] = "Bearer " + value
    return h


def test_verified_access_token_resolves_only_registered_membership(verifier):
    auth, key, loader, _ = verifier
    assert auth.authenticate_request(request(token(key))) == Principal(
        "alice", "personal", Role.DEPLOYER, LoginSource.EXTERNAL_IDP
    )
    assert auth.authenticate_request(request(token(key))) is not None
    loader.assert_called_once_with(ISSUER)
    assert (
        auth.authenticate_request(
            request(
                token(key, sub="unregistered", email="alice@company.test", **{"cognito:groups": ["admin"]})
            )
        )
        is None
    )


@pytest.mark.parametrize(
    "change",
    [
        {"token_use": "id"},
        {"iss": "https://evil.test"},
        {"client_id": "other"},
        {"exp": 1},
        {"exp": True},
        {"iat": int(time.time()) + 3600},
        {"nbf": int(time.time()) + 3600},
        {"scope": "other"},
        {"scope": [SCOPE]},
        {"sub": ""},
        {"sub": None},
        {"exp": None},
    ],
)
def test_wrong_context_or_invalid_claims_fail_closed(verifier, change):
    auth, key, _, _ = verifier
    assert auth.authenticate_request(request(token(key, **change))) is None


def test_forged_signature_and_wrong_algorithms_rejected(verifier):
    auth, key, _, _ = verifier
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert auth.authenticate_request(request(token(other))) is None
    good = token(key)
    payload = json.loads(base64.urlsafe_b64decode(good.split(".")[1] + "=="))
    forged = jwt.encode(payload, "x" * 40, algorithm="HS256", headers={"kid": KID})
    assert auth.authenticate_request(request(forged)) is None
    unsigned = jwt.encode(payload, "", algorithm="none", headers={"kid": KID})
    assert auth.authenticate_request(request(unsigned)) is None


def test_duplicate_authorization_and_query_or_alb_identity_cannot_authenticate(verifier):
    auth, key, _, _ = verifier
    h = request(token(key))
    h["Authorization"] = h["Authorization"]
    assert auth.authenticate_request(h) is None
    assert auth.authenticate_request({"x-amzn-oidc-data": token(key)}) is None
    assert auth.authenticate_request({"Cookie": "token=" + token(key)}) is None


def test_unknown_key_fetches_are_bounded_and_rotation_is_supported(verifier):
    auth, key, loader, now = verifier
    assert auth.authenticate_request(request(token(key))) is not None
    payload = jwt.decode(token(key), options={"verify_signature": False})
    rotated = jwt.encode(payload, key, algorithm="RS256", headers={"kid": "new-key"})
    for _ in range(5):
        assert auth.authenticate_request(request(rotated)) is None
    assert loader.call_count == 1
    loader.return_value = {"keys": [{**loader.return_value["keys"][0], "kid": "new-key"}]}
    now[0] += 61
    assert auth.authenticate_request(request(rotated)) is not None
    assert loader.call_count == 2


def test_fetch_failure_does_not_accept_stale_expired_key(verifier):
    auth, key, loader, now = verifier
    assert auth.authenticate_request(request(token(key))) is not None
    now[0] += 301
    loader.side_effect = OSError("offline")
    assert auth.authenticate_request(request(token(key))) is None
    assert auth.authenticate_request(request(token(key))) is None
    assert loader.call_count == 2


@pytest.mark.parametrize(
    "issuer",
    [
        "http://evil.test",
        "https://evil.test",
        ISSUER + "/",
        ISSUER + "?url=evil",
        ISSUER.replace("/ap-northeast-2_", "/us-east-1_"),
    ],
)
def test_only_configured_regional_pool_urls_are_accepted(issuer):
    with pytest.raises(ValueError):
        CognitoSettings(issuer, CLIENT, (SCOPE,))


def documents():
    return (
        json.dumps({"version": 1, "issuer": ISSUER, "client_id": CLIENT, "required_scopes": [SCOPE]}),
        json.dumps(
            {
                "version": 1,
                "members": [
                    {
                        "issuer": ISSUER,
                        "subject": "subject-1",
                        "user_id": "alice",
                        "organization_id": "personal",
                        "role": "deployer",
                        "enabled": True,
                    }
                ],
            }
        ),
    )


def test_environment_mode_is_exclusive_and_validated(monkeypatch):
    settings, members = documents()
    monkeypatch.setenv("SKY_COGNITO_AUTH_JSON", settings)
    monkeypatch.setenv("SKY_MEMBERSHIPS_JSON", members)
    args = Namespace(auth_mode="cognito", alb_trusts_file=None, memberships_file=None)
    assert isinstance(preparation_identity(args), CognitoRequestAuthenticator)
    with patch.dict("os.environ", {"SKY_PRIVATE_OPERATOR_JSON": "private"}), pytest.raises(ValueError):
        preparation_identity(args)
    args.auth_mode = "alb"
    with pytest.raises(ValueError, match="explicit cognito"):
        preparation_identity(args)


@pytest.mark.parametrize("extra", [[], ["--origin", "http://localhost"], ["--origin", "https://sky.test"]])
def test_cli_refuses_incomplete_or_insecure_cognito_configuration(extra, capsys):
    with pytest.raises(SystemExit) as error:
        main(["api", "--auth-mode", "cognito", "--enable-preparation", *extra])
    assert error.value.code == 2
    assert "Cognito" in capsys.readouterr().err


def test_real_http_enforces_signed_membership_and_origin(verifier):
    auth, key, _, _ = verifier
    preparation = Mock()
    app = DatabasePreparationApp(Mock(), Mock(), preparation, authenticator=auth, origin="https://sky.test")
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for_preparation(app))
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()

    def call(path, method="GET", headers=None):
        c = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        try:
            c.request(method, path, headers=headers or {})
            r = c.getresponse()
            r.read()
            return r.status
        finally:
            c.close()

    try:
        assert call("/api/config") == 403
        headers = {"Authorization": "Bearer " + token(key)}
        assert call("/api/config", headers=headers) == 200
        assert call("/api/config", headers={"Authorization": "Bearer " + token(key, sub="stranger")}) == 403
        assert call("/api/deployment-previews", "POST", {**headers, "Origin": "https://evil.test"}) == 403
        preparation.upload.assert_not_called()
    finally:
        server.shutdown()
        server.server_close()
        worker.join(5)


def test_jwks_download_uses_only_configured_endpoint_and_is_bounded():
    response = Mock()
    response.read.return_value = b'{"keys":[]}'
    opener = Mock()
    opener.open.return_value.__enter__ = Mock(return_value=response)
    opener.open.return_value.__exit__ = Mock(return_value=False)
    with patch("urllib.request.build_opener", return_value=opener):
        assert fetch_jwks(ISSUER) == {"keys": []}
        opener.open.assert_called_once_with(ISSUER + "/.well-known/jwks.json", timeout=3)
        response.read.assert_called_once_with(65_537)
        response.read.return_value = b"x" * 65_537
        with pytest.raises(ValueError):
            fetch_jwks(ISSUER)


@pytest.mark.parametrize("mutation", ["empty", "duplicate", "wrong_alg", "bad_key"])
def test_malformed_key_sets_fail_closed(verifier, mutation):
    auth, key, loader, _ = verifier
    entry = loader.return_value["keys"][0]
    loader.return_value = {
        "empty": {"keys": []},
        "duplicate": {"keys": [entry, entry]},
        "wrong_alg": {"keys": [{**entry, "alg": "HS256"}]},
        "bad_key": {"keys": [{**entry, "n": "AA"}]},
    }[mutation]
    assert auth.authenticate_request(request(token(key))) is None


def test_cli_dispatches_valid_cognito_configuration_without_calling_legacy_app(monkeypatch):
    settings, members = documents()
    monkeypatch.setenv("SKY_COGNITO_AUTH_JSON", settings)
    monkeypatch.setenv("SKY_MEMBERSHIPS_JSON", members)
    with patch("interfaces.b_preparation_runtime.run_preparation_api") as run:
        main(["api", "--auth-mode", "cognito", "--enable-preparation", "--origin", "https://sky.test"])
    assert run.call_args.args[0].auth_mode == "cognito"


@pytest.mark.parametrize(
    "header", [{"jku": "https://evil.test/key"}, {"jwk": {}}, {"x5u": "https://evil.test"}, {"crit": []}]
)
def test_token_cannot_choose_a_key_source_or_extensions(verifier, header):
    auth, key, loader, _ = verifier
    claims = jwt.decode(token(key), options={"verify_signature": False})
    value = jwt.encode(claims, key, algorithm="RS256", headers={"kid": KID, **header})
    assert auth.authenticate_request(request(value)) is None
    loader.assert_not_called()


def test_duplicate_signed_claims_are_rejected(verifier):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    auth, key, loader, _ = verifier

    def part(value):
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    claims = json.dumps(jwt.decode(token(key), options={"verify_signature": False}))
    duplicated = claims[:-1] + ',"client_id":' + json.dumps(CLIENT) + "}"
    unsigned = part(json.dumps({"alg": "RS256", "kid": KID}).encode()) + "." + part(duplicated.encode())
    value = unsigned + "." + part(key.sign(unsigned.encode(), padding.PKCS1v15(), hashes.SHA256()))
    assert auth.authenticate_request(request(value)) is None
    loader.assert_not_called()
