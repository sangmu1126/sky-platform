"""ECR manifest bytes for a workflow-bound result; no image execution or safety claim."""

import hashlib
import json
import re

from adapters.aws.build_image import EcrBuildVerifier
from adapters.aws.recovery_image import CONFIG, MEDIA
from ports.remote_builds import validate_result


class EcrSourceBuildVerifier(EcrBuildVerifier):
    def verify(self, request, result, *, guard):
        validate_result(result, request, result["run_id"])
        guard()
        super().verify(request, result)
        guard()
        response = self.client.batch_get_image(
            registryId=self.settings.account_id,
            repositoryName="sky-managed",
            imageIds=[{"imageDigest": result["image_digest"]}],
        )
        images = response.get("images", [])
        if response.get("failures") or len(images) != 1:
            raise ValueError("One exact built manifest required")
        image = images[0]
        raw = image.get("imageManifest")
        if (
            image.get("registryId") != request["account_id"]
            or image.get("repositoryName") != "sky-managed"
            or image.get("imageId", {}).get("imageDigest") != result["image_digest"]
            or not isinstance(raw, str)
            or len(raw.encode()) > 4 * 1024 * 1024
            or "sha256:" + hashlib.sha256(raw.encode()).hexdigest() != result["image_digest"]
        ):
            raise ValueError("Built ECR manifest bytes changed")

        def unique(pairs):
            value = {}
            for k, v in pairs:
                if k in value:
                    raise ValueError("Duplicate manifest field")
                value[k] = v
            return value

        manifest = json.loads(raw, object_pairs_hook=unique)
        if not isinstance(manifest, dict) or not isinstance(manifest.get("config"), dict):
            raise ValueError("Single manifest config required")
        descriptor = manifest["config"]
        if (
            type(manifest.get("schemaVersion")) is not int
            or manifest["schemaVersion"] != 2
            or manifest.get("mediaType") not in MEDIA
            or image.get("imageManifestMediaType") != manifest["mediaType"]
            or descriptor.get("mediaType") not in CONFIG
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", descriptor.get("digest", ""))
            or type(descriptor.get("size")) is not int
            or not 0 < descriptor["size"] <= 1024 * 1024
        ):
            raise ValueError("Single image with bounded config descriptor required")
        guard()
        return {
            "image": result["image"],
            "manifest_bytes_verified": True,
            "config_digest": descriptor["digest"],
            "config_descriptor_verified": True,
            "config_bytes_verified": False,
            "workflow_run_id": result["run_id"],
            "request_source_binding_verified": True,
            "signed_provenance_verified": False,
            "image_safety_verified": False,
        }
