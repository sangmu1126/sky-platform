"""AWS ECS and VM Docker application identity stays exact and read only."""

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from adapters.onprem.database_inventory import PinnedVmInventoryCommand
from adapters.runtime.environment_application_evidence import (
    PinnedVmApplicationCommand,
    RegisteredAwsVmEnvironmentRuntimeEvidence,
    RegisteredEcsEnvironmentApplication,
    RegisteredVmEnvironmentApplication,
)
from tests.unit.test_database_transfer import transfer

ACCOUNT = "111111111111"
REGION = "ap-northeast-2"


def environment_sha256(values):
    return hashlib.sha256(json.dumps(sorted(values), separators=(",", ":")).encode()).hexdigest()


def registrations():
    plan = transfer()
    source = RegisteredEcsEnvironmentApplication(
        plan.source,
        f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/rehearsal",
        f"arn:aws:ecs:{REGION}:{ACCOUNT}:task/rehearsal/" + "1" * 32,
        f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/rehearsal:7",
        "application",
        f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/rehearsal@sha256:" + "2" * 64,
        "sha256:" + "2" * 64,
        environment_sha256([("MODE", "rehearsal")]),
        "1.4.0",
        "12345678-1234-1234-1234-123456789012",
        "eni-12345678",
        "10.0.1.4",
        "8.8.8.8",
        "vpc-12345678",
        ("sg-12345678", "sg-23456789"),
        (
            ("sky-application-id", "app"),
            ("sky-managed", "true"),
            ("sky-organization-id", "org"),
            ("sky-owner-ref", "source-owner"),
        ),
        (
            (
                "SKY_GAME_CONFIG",
                f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:rehearsal-config-abc123",
            ),
        ),
        f"arn:aws:iam::{ACCOUNT}:role/rehearsal-execution",
    )
    target = RegisteredVmEnvironmentApplication(
        plan.target,
        "daemon-12345678",
        "3" * 64,
        "sha256:" + "4" * 64,
        "rehearsal-network",
        "rehearsal-config",
        "/app/config",
        environment_sha256([("MODE", "rehearsal")]),
        (
            ("sky-application-id", "app"),
            ("sky-managed", "true"),
            ("sky-organization-id", "org"),
            ("sky-owner-ref", "target-owner"),
        ),
    )
    return plan, source, target


def source_responses(source):
    task = {
        "taskArn": source.task_arn,
        "clusterArn": source.cluster_arn,
        "taskDefinitionArn": source.task_definition_arn,
        "lastStatus": "RUNNING",
        "desiredStatus": "RUNNING",
        "launchType": "FARGATE",
        "platformVersion": source.platform_version,
        "enableExecuteCommand": False,
        "containers": [
            {
                "name": source.container_name,
                "imageDigest": source.image_digest,
            }
        ],
        "attachments": [
            {
                "id": source.network_attachment_id,
                "type": "ElasticNetworkInterface",
                "status": "ATTACHED",
                "details": [
                    {"name": "networkInterfaceId", "value": source.network_interface_id},
                    {"name": "privateIPv4Address", "value": source.private_ip},
                ],
            }
        ],
        "tags": [{"key": key, "value": value} for key, value in source.required_tags],
    }
    interface = {
        "NetworkInterfaceId": source.network_interface_id,
        "Status": "in-use",
        "PrivateIpAddress": source.private_ip,
        "Association": {"PublicIp": source.public_ip},
        "VpcId": source.vpc_id,
        "Groups": [{"GroupId": value} for value in reversed(source.security_groups)],
    }
    definition = {
        "taskDefinitionArn": source.task_definition_arn,
        "executionRoleArn": source.execution_role_arn,
        "containerDefinitions": [
            {
                "name": source.container_name,
                "image": source.image_uri,
                "user": source.user,
                "readonlyRootFilesystem": True,
                "privileged": False,
                "environment": [{"name": "MODE", "value": "rehearsal"}],
                "secrets": [{"name": name, "valueFrom": value} for name, value in source.secret_bindings],
            }
        ],
    }
    return task, interface, definition


def fixture(tmp_path):
    plan, source, target = registrations()
    task, interface, definition = source_responses(source)
    sts = Mock(get_caller_identity=Mock(return_value={"Account": ACCOUNT}))
    ecs = Mock(meta=SimpleNamespace(region_name=REGION))
    ecs.describe_tasks.return_value = {"tasks": [task], "failures": []}
    ecs.describe_task_definition.return_value = {"taskDefinition": definition}
    ec2 = Mock(meta=SimpleNamespace(region_name=REGION))
    ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": [interface]}
    factory = RegisteredAwsVmEnvironmentRuntimeEvidence(
        plan,
        source,
        target,
        sts=sts,
        ecs=ecs,
        ec2=ec2,
    )
    key, hosts = tmp_path / "key", tmp_path / "known_hosts"
    key.write_text("private")
    hosts.write_text(
        "[127.0.0.1]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g\n"
    )
    key.chmod(0o600)
    hosts.chmod(0o600)
    ssh = PinnedVmInventoryCommand(
        host="127.0.0.1",
        user="operator",
        port=2222,
        private_key=key,
        known_hosts=hosts,
        private_key_sha256=hashlib.sha256(key.read_bytes()).hexdigest(),
        known_hosts_sha256=hashlib.sha256(hosts.read_bytes()).hexdigest(),
    )
    container = {
        "Id": target.container_id,
        "Image": target.image_id,
        "State": {"Running": True},
        "HostConfig": {
            "ReadonlyRootfs": True,
            "Privileged": False,
            "NetworkMode": target.network_name,
        },
        "Config": {
            "User": target.user,
            "Labels": dict(target.required_labels),
            "Env": ["MODE=rehearsal"],
        },
        "Mounts": [
            {
                "Type": "volume",
                "Name": target.config_volume,
                "Destination": target.config_destination,
                "RW": False,
            }
        ],
        "NetworkSettings": {"Networks": {target.network_name: {}}},
    }
    return factory, ssh, task, interface, definition, container


def test_bound_runtime_evidence_verifies_exact_source_and_target_identities(tmp_path):
    factory, ssh, _task, _interface, _definition, container = fixture(tmp_path)
    with patch(
        "adapters.runtime.environment_application_evidence.bounded_command",
        side_effect=[
            (0, json.dumps(factory.target.daemon_id)),
            (0, json.dumps([container])),
        ],
    ) as command:
        verifier = factory.bind(ssh)
        assert verifier.reference == factory.reference
        assert verifier(factory.transfer.document()["source"]) is True
        assert verifier(factory.transfer.document()["target"]) is True
    assert factory.reference.startswith("RVR-")
    assert command.call_count == 2
    factory.sts.get_caller_identity.assert_called_once_with()
    factory.ecs.describe_tasks.assert_called_once()
    factory.ecs.describe_task_definition.assert_called_once()
    factory.ec2.describe_network_interfaces.assert_called_once()


@pytest.mark.parametrize(
    "side,change",
    [
        ("source", "task"),
        ("source", "network"),
        ("source", "definition"),
        ("source", "source-environment"),
        ("target", "daemon"),
        ("target", "privileged"),
        ("target", "mount"),
        ("target", "target-environment"),
    ],
)
def test_runtime_identity_drift_is_sanitized(tmp_path, side, change):
    factory, ssh, task, interface, definition, container = fixture(tmp_path)
    if change == "task":
        task["lastStatus"] = "STOPPED"
    elif change == "network":
        interface["VpcId"] = "vpc-87654321"
    elif change == "definition":
        definition["taskRoleArn"] = f"arn:aws:iam::{ACCOUNT}:role/privileged"
    elif change == "source-environment":
        definition["containerDefinitions"][0]["environment"][0]["value"] = "changed"
    elif change == "privileged":
        container["HostConfig"]["Privileged"] = True
    elif change == "mount":
        container["Mounts"][0]["RW"] = True
    elif change == "target-environment":
        container["Config"]["Env"] = ["MODE=changed"]
    daemon = "changed-daemon" if change == "daemon" else factory.target.daemon_id
    with patch(
        "adapters.runtime.environment_application_evidence.bounded_command",
        side_effect=[(0, json.dumps(daemon)), (0, json.dumps([container]))],
    ):
        verifier = factory.bind(ssh)
        binding = factory.transfer.document()[side]
        with pytest.raises(RuntimeError, match=f"Registered {side} application runtime unavailable"):
            verifier(binding)


def test_pinned_vm_application_command_rejects_arbitrary_docker_access(tmp_path):
    factory, ssh, _task, _interface, _definition, _container = fixture(tmp_path)
    command = PinnedVmApplicationCommand(ssh, factory.target)
    with patch(
        "adapters.runtime.environment_application_evidence.bounded_command",
        return_value=(0, "[]"),
    ) as run:
        command(["inspect", factory.target.container_id])
        assert run.call_args.args[0][-1].startswith("/usr/bin/sudo -n /usr/bin/docker inspect")
        assert run.call_args.kwargs["env"] == ssh.environment
        with pytest.raises(ValueError, match="fixed VM application"):
            command(["exec", factory.target.container_id, "env"])
    assert run.call_count == 1


def test_duplicate_vm_runtime_metadata_is_sanitized(tmp_path):
    factory, ssh, _task, _interface, _definition, _container = fixture(tmp_path)
    with (
        patch(
            "adapters.runtime.environment_application_evidence.bounded_command",
            side_effect=[
                (0, json.dumps(factory.target.daemon_id)),
                (0, '[{"Config":{"User":"1000:1000","User":"0:0"}}]'),
            ],
        ),
        pytest.raises(RuntimeError, match="Registered target application runtime unavailable"),
    ):
        factory.bind(ssh)(factory.transfer.document()["target"])


def test_runtime_factory_reference_changes_with_any_registered_identity():
    plan, source, target = registrations()
    clients = {
        "sts": Mock(get_caller_identity=Mock()),
        "ecs": Mock(meta=SimpleNamespace(region_name=REGION)),
        "ec2": Mock(meta=SimpleNamespace(region_name=REGION)),
    }
    original = RegisteredAwsVmEnvironmentRuntimeEvidence(plan, source, target, **clients)
    changed = RegisteredAwsVmEnvironmentRuntimeEvidence(
        plan,
        replace(
            source,
            image_uri=source.image_uri.rsplit("@", 1)[0] + "@sha256:" + "f" * 64,
            image_digest="sha256:" + "f" * 64,
        ),
        target,
        **clients,
    )
    assert original.reference != changed.reference
