"""Short-lived detached KMS signatures with an operator-pinned public trust key."""

import base64
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from application.build_binding import validate_build_binding
from ports.remote_builds import canonical

ALGORITHM = "ECDSA_SHA_256"
PROTOCOL = "sky-kms-build-signature-v1"


@dataclass(frozen=True)
class KmsBuildSigningIdentity:
    key_arn: str
    public_key_der: bytes

    def __post_init__(self):
        if not isinstance(self.key_arn, str) or not re.fullmatch(
            r"arn:aws:kms:[a-z]{2}-[a-z]+-[0-9]+:[0-9]{12}:key/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
            self.key_arn,
        ):
            raise ValueError("Immutable same-partition KMS key ARN required; aliases are unsupported")
        if not isinstance(self.public_key_der, bytes) or not 64 <= len(self.public_key_der) <= 1024:
            raise ValueError("Pinned DER public key required")
        key = serialization.load_der_public_key(self.public_key_der)
        if (
            not isinstance(key, ec.EllipticCurvePublicKey)
            or not isinstance(key.curve, ec.SECP256R1)
            or (
                key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                != self.public_key_der
            )
        ):
            raise ValueError("Canonical ECC_NIST_P256 public key required")

    @property
    def region(self):
        return self.key_arn.split(":")[3]

    @property
    def account_id(self):
        return self.key_arn.split(":")[4]

    @property
    def fingerprint(self):
        return "sha256:" + hashlib.sha256(self.public_key_der).hexdigest()


def signing_payload(statement, identity, *, now, seconds=900):
    if (
        not isinstance(identity, KmsBuildSigningIdentity)
        or not isinstance(now, datetime)
        or now.tzinfo is None
    ):
        raise ValueError("Pinned signer and timezone-aware issue time required")
    if type(seconds) is not int or not 1 <= seconds <= 3600:
        raise ValueError("Signature validity must be between one second and one hour")
    if not isinstance(statement, dict) or statement.get("protocol") != "sky-build-input-binding-v1":
        raise ValueError("Prepared input-binding record required")
    # Canonical message includes the protocol/key/algorithm/times and all claims.
    # This is a message format, not a new cryptographic primitive.
    return {
        "protocol": PROTOCOL,
        "key_arn": identity.key_arn,
        "algorithm": ALGORITHM,
        "public_key_fingerprint": identity.fingerprint,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=seconds)).isoformat(),
        "statement": statement,
    }


def verify_build_signature(bundle, identity, request, *, image_digest, config_digest, run_id, now):
    if (
        not isinstance(identity, KmsBuildSigningIdentity)
        or not isinstance(now, datetime)
        or now.tzinfo is None
    ):
        raise ValueError("Pinned verification key and current time required")
    if not isinstance(bundle, dict) or set(bundle) != {"payload", "signature"}:
        raise ValueError("Exact detached signature envelope required")
    payload = bundle["payload"]
    if (
        not isinstance(payload, dict)
        or set(payload)
        != {
            "protocol",
            "key_arn",
            "algorithm",
            "public_key_fingerprint",
            "issued_at",
            "expires_at",
            "statement",
        }
        or any(
            payload.get(k) != v
            for k, v in {
                "protocol": PROTOCOL,
                "key_arn": identity.key_arn,
                "algorithm": ALGORITHM,
                "public_key_fingerprint": identity.fingerprint,
            }.items()
        )
    ):
        raise ValueError("Signature trust identity or algorithm mismatch")
    issued, expiry = (
        datetime.fromisoformat(payload["issued_at"]),
        datetime.fromisoformat(payload["expires_at"]),
    )
    if (
        issued.tzinfo is None
        or expiry.tzinfo is None
        or not issued <= now < expiry
        or not (timedelta(0) < expiry - issued <= timedelta(hours=1))
    ):
        raise ValueError("Signature is future-dated, expired or exceeds its permitted lifetime")
    encoded = bundle["signature"]
    if not isinstance(encoded, str) or not 80 <= len(encoded) <= 144:
        raise ValueError("Bounded DER ECDSA signature required")
    signature = base64.b64decode(encoded, validate=True)
    if base64.b64encode(signature).decode() != encoded:
        raise ValueError("Canonical signature encoding required")
    key = serialization.load_der_public_key(identity.public_key_der)
    key.verify(
        signature, hashlib.sha256(canonical(payload)).digest(), ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )
    result = validate_build_binding(
        payload["statement"], request, image_digest=image_digest, config_digest=config_digest, run_id=run_id
    )
    return {
        **result,
        "signature_verified": True,
        "key_arn": identity.key_arn,
        "public_key_fingerprint": identity.fingerprint,
        "expires_at": expiry.isoformat(),
        "workflow_identity_certified_by_provider": False,
        "key_liveness_checked": False,
    }
