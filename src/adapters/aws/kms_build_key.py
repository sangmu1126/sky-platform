"""Observe a pinned signing key; never sign, enable, revoke, or change policies."""

from datetime import UTC, datetime

from application.kms_build_signature import ALGORITHM, KmsBuildSigningIdentity


class AwsKmsBuildKeyObserver:
    def __init__(self, identity, *, session=None, clock=lambda: datetime.now(UTC)):
        if not isinstance(identity, KmsBuildSigningIdentity):
            raise TypeError("Operator-pinned signing identity required")
        self.identity, self.session, self.clock = identity, session, clock

    def observe(self, *, guard):
        identity = self.identity
        guard()
        session = self.session
        if session is None:
            import boto3

            session = boto3.Session(region_name=identity.region)
        from botocore.config import Config

        config = Config(
            retries={"total_max_attempts": 1, "mode": "standard"},
            connect_timeout=5,
            read_timeout=10,
        )
        kms = session.client("kms", region_name=identity.region, config=config)
        sts = session.client("sts", region_name=identity.region, config=config)

        def call(client, method, **kwargs):
            guard()
            result = getattr(client, method)(**kwargs)
            guard()
            return result

        if any(client.meta.region_name != identity.region for client in (kms, sts)) or (
            call(sts, "get_caller_identity").get("Account") != identity.account_id
        ):
            raise ValueError("Registered key account and region required")

        def describe():
            metadata = call(kms, "describe_key", KeyId=identity.key_arn)["KeyMetadata"]
            if (
                metadata.get("Arn") != identity.key_arn
                or metadata.get("KeyId") != identity.key_arn.rsplit("/", 1)[1]
                or metadata.get("AWSAccountId") != identity.account_id
                or metadata.get("KeyState") != "Enabled"
                or metadata.get("Enabled") is not True
                or metadata.get("KeyUsage") != "SIGN_VERIFY"
                or metadata.get("KeySpec") != "ECC_NIST_P256"
                or metadata.get("Origin") != "AWS_KMS"
                or metadata.get("KeyManager") != "CUSTOMER"
                or metadata.get("MultiRegion") is not False
            ):
                raise ValueError("Enabled registered regional signing key required")

        describe()
        public = call(kms, "get_public_key", KeyId=identity.key_arn)
        if (
            public.get("KeyId") != identity.key_arn
            or public.get("PublicKey") != identity.public_key_der
            or public.get("KeySpec") != "ECC_NIST_P256"
            or public.get("KeyUsage") != "SIGN_VERIFY"
            or public.get("SigningAlgorithms") != [ALGORITHM]
        ):
            raise ValueError("Current KMS public key differs from registered trust")
        describe()
        observed = self.clock()
        if not isinstance(observed, datetime) or observed.tzinfo is None or observed.utcoffset() is None:
            raise ValueError("Timezone-aware observation time required")
        guard()
        # KMS reads are eventually consistent. This is a bounded observation,
        # not an atomic fence against a later key/policy change or new execution.
        return {
            "key_arn": identity.key_arn,
            "public_key_fingerprint": identity.fingerprint,
            "algorithm": ALGORITHM,
            "key_state": "Enabled",
            "observed_at": observed.isoformat(),
            "key_liveness_checked": True,
            "read_only": True,
            "state_changed": False,
            "revocation_race_excluded": False,
            "key_policy_audited": False,
            "recovery_authorized": False,
        }
