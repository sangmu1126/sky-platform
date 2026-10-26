"""Sign checked build-binding records; KMS private keys never leave the service."""

import base64
import hashlib
import json
from datetime import UTC, datetime

from application.build_binding import validate_build_binding
from application.kms_build_signature import (
    ALGORITHM,
    KmsBuildSigningIdentity,
    signing_payload,
    verify_build_signature,
)
from ports.remote_builds import canonical


class AwsKmsBuildSigner:
    def __init__(self, identity, *, session=None, clock=lambda: datetime.now(UTC)):
        if not isinstance(identity, KmsBuildSigningIdentity):
            raise TypeError("Operator-pinned KMS signing identity required")
        self.identity, self.session, self.clock = identity, session, clock

    def sign(self, statement, request, *, image_digest, config_digest, run_id, guard, seconds=900):
        # Take detached copies before checking them or handing control to guards.
        statement, request = json.loads(canonical(statement)), json.loads(canonical(request))
        validate_build_binding(
            statement, request, image_digest=image_digest, config_digest=config_digest, run_id=run_id
        )
        identity = self.identity
        if (request["account_id"], request["region"]) != (identity.account_id, identity.region):
            raise ValueError("Build request differs from the registered signing account/region")
        payload = signing_payload(statement, identity, now=self.clock(), seconds=seconds)
        session = self.session
        if session is None:
            import boto3

            session = boto3.Session(region_name=identity.region)
        from botocore.config import Config

        kms = session.client(
            "kms",
            region_name=identity.region,
            config=Config(retries={"total_max_attempts": 1, "mode": "standard"}),
        )
        sts = session.client("sts", region_name=identity.region)

        def call(client, method, **kwargs):
            guard()
            result = getattr(client, method)(**kwargs)
            guard()
            return result

        if any(c.meta.region_name != identity.region for c in (kms, sts)) or (
            call(sts, "get_caller_identity").get("Account") != identity.account_id
        ):
            raise ValueError("Signing account or client region mismatch")
        metadata = call(kms, "describe_key", KeyId=identity.key_arn)["KeyMetadata"]
        if (
            metadata.get("Arn") != identity.key_arn
            or metadata.get("AWSAccountId") != identity.account_id
            or (
                metadata.get("KeyUsage") != "SIGN_VERIFY"
                or metadata.get("KeySpec") != "ECC_NIST_P256"
                or metadata.get("KeyState") != "Enabled"
                or metadata.get("Enabled") is not True
                or metadata.get("MultiRegion") is not False
                or metadata.get("Origin") != "AWS_KMS"
            )
        ):
            raise ValueError("Enabled registered regional KMS signing key required")
        key = call(kms, "get_public_key", KeyId=identity.key_arn)
        if (
            key.get("KeyId") != identity.key_arn
            or key.get("PublicKey") != identity.public_key_der
            or (
                key.get("KeyUsage") != "SIGN_VERIFY"
                or key.get("KeySpec") != "ECC_NIST_P256"
                or ALGORITHM not in key.get("SigningAlgorithms", [])
            )
        ):
            raise ValueError("KMS public key differs from operator trust registration")
        signature = call(
            kms,
            "sign",
            KeyId=identity.key_arn,
            Message=hashlib.sha256(canonical(payload)).digest(),
            MessageType="DIGEST",
            SigningAlgorithm=ALGORITHM,
        )
        if (
            signature.get("KeyId") != identity.key_arn
            or signature.get("SigningAlgorithm") != ALGORITHM
            or (not isinstance(signature.get("Signature"), bytes))
        ):
            raise ValueError("Exact KMS signature response required")
        bundle = {"payload": payload, "signature": base64.b64encode(signature["Signature"]).decode()}
        verify_build_signature(
            bundle,
            identity,
            request,
            image_digest=image_digest,
            config_digest=config_digest,
            run_id=run_id,
            now=self.clock(),
        )
        guard()
        return bundle
