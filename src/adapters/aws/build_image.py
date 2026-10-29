"""Verify remote build results against ECR's current tag and manifest digest."""


class EcrBuildVerifier:
    def __init__(self, settings, *, client=None):
        self.settings = settings
        if client is None:
            import boto3
            from botocore.config import Config

            client = boto3.client(
                "ecr",
                region_name=settings.region,
                config=Config(connect_timeout=5, read_timeout=20, retries={"total_max_attempts": 1}),
            )
        self.client = client

    def verify(self, request, result):
        from botocore.exceptions import BotoCoreError, ClientError

        try:
            response = self.client.batch_get_image(
                registryId=self.settings.account_id,
                repositoryName="sky-managed",
                imageIds=[{"imageTag": "build-" + request["build_id"]}],
            )
        except (BotoCoreError, ClientError):
            raise OSError("Built ECR image verification unavailable") from None
        images = response.get("images", [])
        if (
            response.get("failures")
            or len(images) != 1
            or images[0].get("imageId", {}).get("imageDigest") != result["image_digest"]
        ):
            raise ValueError("Built ECR image no longer matches the result")


class SignedEcrBuildVerifier(EcrBuildVerifier):
    """Bind the current ECR manifest to a short-lived signed, expected request.

    Builder workflow identity must additionally be verified by the dispatcher.
    This checks an input binding, never the absence of malicious application code.
    """

    def __init__(
        self, settings, *, objects, identity, key_observer, client=None, clock=None, require_inspection=False
    ):
        from datetime import UTC, datetime

        self.require_inspection = require_inspection
        from application.kms_build_signature import KmsBuildSigningIdentity

        if not isinstance(identity, KmsBuildSigningIdentity) or key_observer is None:
            raise ValueError("Pinned build signing key and current key observer required")
        if (identity.account_id, identity.region) != (settings.account_id, settings.region):
            raise ValueError("Build verifier signing account/region differs")
        super().__init__(settings, client=client)
        self.objects, self.identity, self.key_observer = objects, identity, key_observer
        self.clock = clock or (lambda: datetime.now(UTC))

    def verify(self, request, result):
        from botocore.exceptions import BotoCoreError, ClientError
        from cryptography.exceptions import InvalidSignature

        try:
            return self._verify(request, result)
        except (BotoCoreError, ClientError):
            raise OSError("Signed build verification unavailable; no deployment permission") from None
        except (InvalidSignature, KeyError, TypeError):
            raise ValueError("Signed build provenance is invalid") from None

    def _verify(self, request, result):
        import json
        from application.kms_build_signature import verify_build_signature
        from ports.image_manifests import verify_image_manifest
        from ports.remote_builds import validate_result

        validate_result(result, request, result["run_id"])
        if (request["account_id"], request["region"]) != (self.settings.account_id, self.settings.region):
            raise ValueError("Expected source account/region differs")
        response = self.client.batch_get_image(
            registryId=self.settings.account_id,
            repositoryName="sky-managed",
            imageIds=[{"imageTag": "build-" + request["build_id"]}],
        )
        images = response.get("images", [])
        if (
            response.get("failures")
            or len(images) != 1
            or images[0].get("imageId", {}).get("imageDigest") != result["image_digest"]
        ):
            raise ValueError("Signed build current manifest differs")
        raw = images[0].get("imageManifest")
        if not isinstance(raw, str) or len(raw.encode()) > 4 * 1024**2:
            raise ValueError("Bounded signed build manifest required")
        config_digest = json.loads(raw).get("config", {}).get("digest")
        verify_image_manifest(raw, result["image_digest"], config_digest)
        bundle = self.objects.read(f"builds/{request['build_id']}/signature.json")
        proof = verify_build_signature(
            bundle,
            self.identity,
            request,
            image_digest=result["image_digest"],
            config_digest=config_digest,
            run_id=result["run_id"],
            now=self.clock(),
        )
        if self.require_inspection and "security" not in bundle["payload"]["statement"]:
            raise ValueError("Hosted image is missing signed security inspection")
        key = self.key_observer.observe(guard=lambda: None)
        if key.get("key_liveness_checked") is not True or key.get("key_arn") != self.identity.key_arn:
            raise ValueError("Build signing key liveness is not verified")
        return {
            **proof,
            "current_registry_manifest_checked": True,
            "key_liveness_checked": True,
            "image_safety_verified": False,
        }
