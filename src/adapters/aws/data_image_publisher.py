"""Push checked bytes through ECR APIs without Docker or registry login tokens."""

import hashlib
import re
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from adapters.build.registry_image import registry_image
from ports.image_manifests import verify_image_manifest


class EcrDataPublisher:
    def __init__(self, *, account_id, region, repository, session, guard, clock=time.monotonic):
        if (
            not isinstance(account_id, str)
            or not re.fullmatch(r"[0-9]{12}", account_id)
            or not isinstance(region, str)
            or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d+", region)
            or not isinstance(repository, str)
            or len(repository) > 128
            or not re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*", repository)
            or not callable(guard)
        ):
            raise ValueError("Registered publisher destination and current execution guard required")
        self.account_id, self.region, self.repository = account_id, region, repository
        self.session, self.guard, self.clock = session, guard, clock

    def publish(self, archive, *, image_id, local_tag, tag, platform="linux/amd64"):
        if not isinstance(tag, str) or not re.fullmatch(
            r"build-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", tag
        ):
            raise ValueError("Immutable build tag required")
        # Archive parsing and preparation precede any client/credential access.
        with registry_image(archive, image_id, local_tag, platform=platform) as prepared:
            self.guard()
            config = Config(connect_timeout=10, read_timeout=60, retries={"total_max_attempts": 1})
            sts = self.session.client("sts", region_name=self.region, config=config)
            ecr = self.session.client("ecr", region_name=self.region, config=config)
            deadline = self.clock() + 600

            def call(client, method, **arguments):
                self.guard()
                if self.clock() >= deadline:
                    raise OSError("Data-only publication exceeded deadline; reconcile existing state")
                response = getattr(client, method)(**arguments)
                self.guard()
                return response

            if call(sts, "get_caller_identity").get("Account") != self.account_id:
                raise ValueError("Publisher account differs from registration")
            scope = {"registryId": self.account_id, "repositoryName": self.repository}
            repositories = call(
                ecr, "describe_repositories", registryId=self.account_id, repositoryNames=[self.repository]
            ).get("repositories")
            arn = f"arn:aws:ecr:{self.region}:{self.account_id}:repository/{self.repository}"
            if (
                not isinstance(repositories, list)
                or len(repositories) != 1
                or repositories[0].get("repositoryArn") != arn
                or repositories[0].get("imageTagMutability") != "IMMUTABLE"
            ):
                raise ValueError("Exact immutable owned registry repository required")
            tags = call(ecr, "list_tags_for_resource", resourceArn=arn).get("tags", [])
            if {item.get("Key"): item.get("Value") for item in tags}.get("app") != "sky":
                raise ValueError("Publisher repository ownership tag differs")
            try:
                call(ecr, "describe_images", **scope, imageIds=[{"imageTag": tag}])
            except ClientError as error:
                if error.response.get("Error", {}).get("Code") != "ImageNotFoundException":
                    raise
            else:
                raise ValueError("Existing image requires reconciliation, never overwrite")
            for digest, path in prepared["blobs"].items():
                # Recheck bytes at the actual upload boundary. Never extract a layer.
                with path.open("rb") as data:
                    if "sha256:" + hashlib.file_digest(data, "sha256").hexdigest() != digest:
                        raise ValueError("Prepared registry blob changed")
                    availability = call(ecr, "batch_check_layer_availability", **scope, layerDigests=[digest])
                    if availability.get("failures"):
                        raise ValueError("Registry layer availability is uncertain")
                    layers = availability.get("layers", [])
                    if len(layers) != 1 or layers[0].get("layerDigest") != digest:
                        raise ValueError("Registry layer availability identity differs")
                    if layers[0].get("layerAvailability") == "AVAILABLE":
                        continue
                    if layers[0].get("layerAvailability") != "UNAVAILABLE":
                        raise ValueError("Registry layer availability is unknown")
                    data.seek(0)
                    upload = call(ecr, "initiate_layer_upload", **scope)
                    part_size, upload_id = upload.get("partSize"), upload.get("uploadId")
                    if (
                        type(part_size) is not int
                        or not 5 * 1024**2 <= part_size <= 20 * 1024**2
                        or not isinstance(upload_id, str)
                        or not re.fullmatch(r"[A-Za-z0-9-]{1,128}", upload_id)
                    ):
                        raise ValueError("Bounded registry upload contract required")
                    offset = 0
                    while chunk := data.read(part_size):
                        part = call(
                            ecr,
                            "upload_layer_part",
                            **scope,
                            uploadId=upload_id,
                            partFirstByte=offset,
                            partLastByte=offset + len(chunk) - 1,
                            layerPartBlob=chunk,
                        )
                        offset += len(chunk)
                        if (
                            part.get("uploadId") != upload_id
                            or part.get("lastByteReceived") != offset - 1
                            or part.get("registryId") != self.account_id
                            or part.get("repositoryName") != self.repository
                        ):
                            raise ValueError("Registry part acknowledgment differs")
                    completed = call(
                        ecr, "complete_layer_upload", **scope, uploadId=upload_id, layerDigests=[digest]
                    )
                    if completed.get("layerDigest") != digest:
                        raise ValueError("Registry completed a different blob")
            result = call(
                ecr,
                "put_image",
                **scope,
                imageTag=tag,
                imageManifest=prepared["manifest"].decode(),
                imageManifestMediaType=prepared["media_type"],
                imageDigest=prepared["digest"],
            )
            if result.get("image", {}).get("imageId", {}).get("imageDigest") != prepared["digest"]:
                raise ValueError("Registry manifest identity differs after publication")
            observed = call(
                ecr,
                "batch_get_image",
                **scope,
                imageIds=[{"imageDigest": prepared["digest"]}],
                acceptedMediaTypes=[prepared["media_type"]],
            )
            images = observed.get("images", [])
            if (
                observed.get("failures")
                or len(images) != 1
                or images[0].get("imageId", {}).get("imageDigest") != prepared["digest"]
            ):
                raise ValueError("Published manifest observation is incomplete")
            verify_image_manifest(images[0].get("imageManifest"), prepared["digest"], image_id)
            return {
                "image": f"{self.account_id}.dkr.ecr.{self.region}.amazonaws.com/{self.repository}@{prepared['digest']}",
                "image_digest": prepared["digest"],
                "config_digest": image_id,
                "manifest": prepared["manifest"].decode(),
                "code_executed": False,
                "docker_daemon_used": False,
                "registry_login_token_requested": False,
            }
