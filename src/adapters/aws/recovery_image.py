"""Read exact ECR manifest bytes; never execute images or infer source provenance."""

import hashlib
import json
from datetime import UTC, datetime

from domain.recovery_image import RecoveryImageRegistration

MEDIA = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
CONFIG = {
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
}


class AwsRecoveryImageInspector:
    def __init__(self, *, session=None, clock=lambda: datetime.now(UTC), provenance=None):
        self.session, self.clock, self.provenance = session, clock, provenance

    def inspect(self, registration, *, guard):
        if not isinstance(registration, RecoveryImageRegistration):
            raise TypeError("Validated operator image registration required")
        session = self.session
        if session is None:
            import boto3

            session = boto3.Session(region_name=registration.region)
        ecr, sts = (
            session.client(name, region_name=registration.region)
            for name in ("ecr", "sts")
        )

        def call(client, method, **kwargs):
            guard()
            result = getattr(client, method)(**kwargs)
            guard()
            return result

        if any(c.meta.region_name != registration.region for c in (ecr, sts)):
            raise ValueError("Recovery image client region mismatch")
        if call(sts, "get_caller_identity").get("Account") != registration.account_id:
            raise ValueError("Recovery image observer account mismatch")
        response = call(
            ecr,
            "batch_get_image",
            registryId=registration.account_id,
            repositoryName=registration.repository,
            imageIds=[{"imageDigest": registration.manifest_digest}],
        )
        images = response.get("images")
        if response.get("failures") or not isinstance(images, list) or len(images) != 1:
            raise ValueError("One exact recovery image manifest required")
        image = images[0]
        raw = image.get("imageManifest")
        if (
            image.get("registryId") != registration.account_id
            or image.get("repositoryName") != registration.repository
            or image.get("imageId", {}).get("imageDigest")
            != registration.manifest_digest
            or not isinstance(raw, str)
            or len(raw.encode()) > 4 * 1024 * 1024
            or "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
            != registration.manifest_digest
        ):
            raise ValueError(
                "Recovery manifest identity or bytes differ from operator pin"
            )

        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("Duplicate image manifest field")
                value[key] = item
            return value

        manifest = json.loads(raw, object_pairs_hook=unique)
        if (
            not isinstance(manifest, dict)
            or type(manifest.get("schemaVersion")) is not int
            or manifest["schemaVersion"] != 2
            or manifest.get("mediaType") not in MEDIA
            or image.get("imageManifestMediaType") != manifest["mediaType"]
            or not isinstance(manifest.get("config"), dict)
            or manifest["config"].get("mediaType") not in CONFIG
            or manifest["config"].get("digest") != registration.config_digest
        ):
            raise ValueError(
                "Single image manifest/config required; indexes require separate review"
            )
        provenance = None
        if self.provenance is not None:
            provenance = self.provenance.verify(registration, raw.encode(), guard=guard)
        checked = self.clock()
        if not isinstance(checked, datetime) or checked.tzinfo is None:
            raise ValueError("Timezone-aware image observation required")
        guard()
        return {
            "image": registration.image,
            "config_digest": registration.config_digest,
            "manifest_bytes_verified": True,
            "config_descriptor_verified": True,
            "source_provenance_verified": False,
            "image_safety_verified": False,
            "recovery_authorized": False,
            "state_changed": False,
            "read_only": True,
            "observed_at": checked.isoformat(),
            **({"provenance": provenance} if self.provenance is not None else {}),
        }
