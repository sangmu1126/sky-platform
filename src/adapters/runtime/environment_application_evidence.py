"""Read-only AWS ECS and VM Docker identity for one environment transfer."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import shlex
from dataclasses import asdict, dataclass

from adapters.build.process import bounded_command
from adapters.onprem.database_inventory import PinnedVmInventoryCommand
from adapters.runtime.strict_json import strict_external_json
from domain.database_migration import DatabasePlacement
from domain.database_transfer import RegisteredDatabaseTransfer
from domain.environment_transition import _ref


def _canonical_pairs(values, label):
    if (
        not isinstance(values, tuple)
        or not values
        or tuple(sorted(values)) != values
        or len(dict(values)) != len(values)
        or any(
            not isinstance(key, str)
            or not isinstance(value, str)
            or not key
            or not value
            or len(key) > 128
            or len(value) > 512
            for key, value in values
        )
    ):
        raise ValueError(f"Canonical {label} required")


def _bounded(value, label, maximum=1024):
    if (
        not isinstance(value, str)
        or not 1 <= len(value.encode()) <= maximum
        or any(ord(character) < 33 for character in value)
    ):
        raise ValueError(f"Bounded {label} required")


def _pairs_sha256(values):
    return hashlib.sha256(
        json.dumps(sorted(values), separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def _aws_environment(values):
    if (
        not isinstance(values, list)
        or len(values) > 256
        or any(
            not isinstance(value, dict)
            or set(value) != {"name", "value"}
            or not isinstance(value["name"], str)
            or not isinstance(value["value"], str)
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", value["name"])
            or len(value["value"].encode()) > 8192
            or "\x00" in value["value"]
            for value in values
        )
    ):
        raise ValueError("Canonical ECS environment required")
    pairs = [(value["name"], value["value"]) for value in values]
    if len(dict(pairs)) != len(pairs):
        raise ValueError("Distinct ECS environment names required")
    return _pairs_sha256(pairs)


def _docker_environment(values):
    if (
        not isinstance(values, list)
        or len(values) > 256
        or any(
            not isinstance(value, str)
            or "=" not in value
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", value.split("=", 1)[0])
            or len(value.encode()) > 8320
            or "\x00" in value
            for value in values
        )
    ):
        raise ValueError("Canonical VM environment required")
    pairs = [value.split("=", 1) for value in values]
    if len({value[0] for value in pairs}) != len(pairs):
        raise ValueError("Distinct VM environment names required")
    return _pairs_sha256(pairs)


@dataclass(frozen=True)
class RegisteredEcsEnvironmentApplication:
    placement: DatabasePlacement
    cluster_arn: str
    task_arn: str
    task_definition_arn: str
    container_name: str
    image_uri: str
    image_digest: str
    environment_sha256: str
    platform_version: str
    network_attachment_id: str
    network_interface_id: str
    private_ip: str
    public_ip: str | None
    vpc_id: str
    security_groups: tuple[str, ...]
    required_tags: tuple[tuple[str, str], ...]
    secret_bindings: tuple[tuple[str, str], ...]
    execution_role_arn: str
    user: str = "1000:1000"

    def __post_init__(self):
        if not isinstance(self.placement, DatabasePlacement) or self.placement.location.provider != "aws":
            raise ValueError("AWS source application placement required")
        account, region = self.placement.location.authority_ref, self.placement.location.location
        patterns = (
            (self.cluster_arn, rf"arn:aws:ecs:{region}:{account}:cluster/[A-Za-z0-9_./-]{{1,255}}"),
            (self.task_arn, rf"arn:aws:ecs:{region}:{account}:task/[A-Za-z0-9_./-]{{1,255}}"),
            (
                self.task_definition_arn,
                rf"arn:aws:ecs:{region}:{account}:task-definition/[A-Za-z0-9_-]{{1,255}}:\d+",
            ),
            (
                self.execution_role_arn,
                rf"arn:aws:iam::{account}:role/[A-Za-z0-9+=,.@_/-]{{1,512}}",
            ),
        )
        if any(not re.fullmatch(pattern, value) for value, pattern in patterns):
            raise ValueError("Canonical ECS runtime identities required")
        _ref(self.container_name)
        _bounded(self.image_uri, "ECS image URI")
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", self.image_digest) or not self.image_uri.endswith(
            "@" + self.image_digest
        ):
            raise ValueError("Pinned ECS image digest required")
        if not re.fullmatch(r"[a-f0-9]{64}", self.environment_sha256) or not re.fullmatch(
            r"[0-9]+(?:[.][0-9]+){1,3}", self.platform_version
        ):
            raise ValueError("Pinned ECS environment and platform required")
        if not re.fullmatch(
            r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
            self.network_attachment_id,
        ):
            raise ValueError("Pinned ECS network attachment required")
        if not re.fullmatch(r"eni-[a-f0-9]{8,17}", self.network_interface_id):
            raise ValueError("Pinned ECS network interface required")
        private = ipaddress.ip_address(self.private_ip)
        if not private.is_private or private.is_unspecified or private.is_multicast:
            raise ValueError("Private ECS task address required")
        if self.public_ip is not None:
            public = ipaddress.ip_address(self.public_ip)
            if public.is_private or public.is_unspecified or public.is_multicast:
                raise ValueError("Public ECS task address required")
        if not re.fullmatch(r"vpc-[a-f0-9]{8,17}", self.vpc_id):
            raise ValueError("Pinned ECS VPC required")
        if (
            not isinstance(self.security_groups, tuple)
            or not self.security_groups
            or tuple(sorted(self.security_groups)) != self.security_groups
            or len(set(self.security_groups)) != len(self.security_groups)
            or any(not re.fullmatch(r"sg-[a-f0-9]{8,17}", value) for value in self.security_groups)
        ):
            raise ValueError("Canonical ECS security groups required")
        _canonical_pairs(self.required_tags, "ECS ownership tags")
        tags = dict(self.required_tags)
        if (
            tags.get("sky-managed") != "true"
            or tags.get("sky-organization-id") != self.placement.organization_id
            or tags.get("sky-application-id") != self.placement.application_id
            or tags.get("sky-owner-ref") != self.placement.owner_ref
        ):
            raise ValueError("Owned ECS application tags required")
        _canonical_pairs(self.secret_bindings, "ECS secret bindings")
        secret_prefix = f"arn:aws:secretsmanager:{region}:{account}:secret:"
        if any(
            not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name) or not value.startswith(secret_prefix)
            for name, value in self.secret_bindings
        ):
            raise ValueError("Pinned ECS secret bindings required")
        if self.user != "1000:1000":
            raise ValueError("Unprivileged ECS application user required")


@dataclass(frozen=True)
class RegisteredVmEnvironmentApplication:
    placement: DatabasePlacement
    daemon_id: str
    container_id: str
    image_id: str
    network_name: str
    config_volume: str
    config_destination: str
    environment_sha256: str
    required_labels: tuple[tuple[str, str], ...]
    user: str = "1000:1000"

    def __post_init__(self):
        if not isinstance(self.placement, DatabasePlacement) or self.placement.location.provider != "onprem":
            raise ValueError("VM target application placement required")
        if not re.fullmatch(r"[A-Za-z0-9:-]{8,128}", self.daemon_id):
            raise ValueError("Pinned VM Docker daemon required")
        if not re.fullmatch(r"[a-f0-9]{64}", self.container_id) or not re.fullmatch(
            r"sha256:[a-f0-9]{64}", self.image_id
        ):
            raise ValueError("Pinned VM application container and image required")
        for value in (self.network_name, self.config_volume):
            _ref(value)
        if (
            not isinstance(self.config_destination, str)
            or not self.config_destination.startswith("/")
            or ".." in self.config_destination.split("/")
            or any(ord(character) < 32 for character in self.config_destination)
        ):
            raise ValueError("Pinned VM application configuration mount required")
        if not re.fullmatch(r"[a-f0-9]{64}", self.environment_sha256):
            raise ValueError("Pinned VM application environment required")
        _canonical_pairs(self.required_labels, "VM application ownership labels")
        labels = dict(self.required_labels)
        if (
            labels.get("sky-managed") != "true"
            or labels.get("sky-organization-id") != self.placement.organization_id
            or labels.get("sky-application-id") != self.placement.application_id
            or labels.get("sky-owner-ref") != self.placement.owner_ref
        ):
            raise ValueError("Owned VM application labels required")
        if self.user != "1000:1000":
            raise ValueError("Unprivileged VM application user required")


class PinnedVmApplicationCommand:
    """Permit only daemon identity and one registered application inspection."""

    def __init__(self, ssh, registration):
        if not isinstance(ssh, PinnedVmInventoryCommand) or not isinstance(
            registration, RegisteredVmEnvironmentApplication
        ):
            raise TypeError("Pinned SSH and VM application registration required")
        self.ssh, self.registration = ssh, registration

    def __call__(self, arguments):
        allowed = arguments == ["info", "--format", "{{json .ID}}"] or arguments == [
            "inspect",
            self.registration.container_id,
        ]
        if not allowed:
            raise ValueError("Only fixed VM application inventory commands permitted")
        code, output = bounded_command(
            [
                *self.ssh.arguments,
                shlex.join(["/usr/bin/sudo", "-n", "/usr/bin/docker", *arguments]),
            ],
            timeout=15,
            output_limit=128 * 1024,
            env=self.ssh.environment,
        )
        if code:
            raise RuntimeError("Pinned VM application inventory unavailable")
        return output


class RegisteredAwsVmEnvironmentRuntimeEvidence:
    """Factory bound to the resolver's short-lived SSH files at runtime."""

    def __init__(self, transfer, source, target, *, sts, ecs, ec2):
        if not isinstance(transfer, RegisteredDatabaseTransfer):
            raise TypeError("Registered environment transfer required")
        if not isinstance(source, RegisteredEcsEnvironmentApplication) or not isinstance(
            target, RegisteredVmEnvironmentApplication
        ):
            raise TypeError("Registered AWS and VM applications required")
        if (source.placement, target.placement) != (transfer.source, transfer.target):
            raise ValueError("Application runtimes differ from registered transfer")
        if (
            not callable(getattr(sts, "get_caller_identity", None))
            or not callable(getattr(ecs, "describe_tasks", None))
            or not callable(getattr(ecs, "describe_task_definition", None))
            or not callable(getattr(ec2, "describe_network_interfaces", None))
        ):
            raise TypeError("Read-only AWS application clients required")
        region = source.placement.location.location
        if any(getattr(getattr(value, "meta", None), "region_name", None) != region for value in (ecs, ec2)):
            raise ValueError("AWS application clients differ from registered region")
        self.transfer, self.source, self.target = transfer, source, target
        self.sts, self.ecs, self.ec2 = sts, ecs, ec2
        value = {
            "schema_version": 1,
            "profile": "registered_aws_vm_environment_runtime_evidence_v1",
            "transfer": transfer.document(),
            "source": asdict(source),
            "target": asdict(target),
        }
        self.reference = (
            "RVR-"
            + hashlib.sha256(
                json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            ).hexdigest()
        )

    def bind(self, ssh):
        return _BoundAwsVmEnvironmentRuntimeEvidence(
            self,
            PinnedVmApplicationCommand(ssh, self.target),
        )


class _BoundAwsVmEnvironmentRuntimeEvidence:
    def __init__(self, registration, vm_command):
        self.registration, self.vm_command = registration, vm_command
        self.reference = registration.reference

    def _source(self):
        r = self.registration
        source = r.source
        try:
            if r.sts.get_caller_identity().get("Account") != source.placement.location.authority_ref:
                raise ValueError("AWS account changed")
            response = r.ecs.describe_tasks(
                cluster=source.cluster_arn,
                tasks=[source.task_arn],
                include=["TAGS"],
            )
            tasks = response.get("tasks", [])
            failures = response.get("failures", [])
            if len(tasks) != 1 or failures:
                raise ValueError("Registered ECS task unavailable")
            task = tasks[0]
            containers = task.get("containers", [])
            raw_tags = task.get("tags", [])
            tags = {value["key"]: value["value"] for value in raw_tags}
            attachments = task.get("attachments", [])
            if len(raw_tags) != len(tags) or len(attachments) != 1:
                raise ValueError("Canonical ECS task evidence required")
            attachment = attachments[0]
            details = {value["name"]: value["value"] for value in attachment.get("details", [])}
            if (
                task.get("taskArn") != source.task_arn
                or task.get("clusterArn") != source.cluster_arn
                or task.get("taskDefinitionArn") != source.task_definition_arn
                or task.get("lastStatus") != "RUNNING"
                or task.get("desiredStatus") != "RUNNING"
                or task.get("launchType") != "FARGATE"
                or task.get("platformVersion") != source.platform_version
                or task.get("enableExecuteCommand", False) is not False
                or len(containers) != 1
                or containers[0].get("name") != source.container_name
                or containers[0].get("imageDigest") != source.image_digest
                or attachment.get("id") != source.network_attachment_id
                or attachment.get("type") != "ElasticNetworkInterface"
                or attachment.get("status") != "ATTACHED"
                or details.get("networkInterfaceId") != source.network_interface_id
                or details.get("privateIPv4Address") != source.private_ip
                or any(tags.get(key) != value for key, value in source.required_tags)
            ):
                raise ValueError("Registered ECS task identity changed")
            (interface,) = r.ec2.describe_network_interfaces(
                NetworkInterfaceIds=[source.network_interface_id]
            )["NetworkInterfaces"]
            association = interface.get("Association", {})
            if (
                interface.get("NetworkInterfaceId") != source.network_interface_id
                or interface.get("Status") != "in-use"
                or interface.get("PrivateIpAddress") != source.private_ip
                or association.get("PublicIp") != source.public_ip
                or interface.get("VpcId") != source.vpc_id
                or tuple(sorted(value["GroupId"] for value in interface.get("Groups", [])))
                != source.security_groups
            ):
                raise ValueError("Registered ECS network identity changed")
            definition = r.ecs.describe_task_definition(taskDefinition=source.task_definition_arn)[
                "taskDefinition"
            ]
            containers = definition.get("containerDefinitions", [])
            if (
                definition.get("taskDefinitionArn") != source.task_definition_arn
                or definition.get("taskRoleArn") is not None
                or definition.get("executionRoleArn") != source.execution_role_arn
                or len(containers) != 1
            ):
                raise ValueError("Registered ECS task definition changed")
            container = containers[0]
            observed_secrets = tuple(
                sorted((value["name"], value["valueFrom"]) for value in container.get("secrets", []))
            )
            if (
                container.get("name") != source.container_name
                or container.get("image") != source.image_uri
                or container.get("user") != source.user
                or container.get("readonlyRootFilesystem") is not True
                or container.get("privileged", False) is not False
                or _aws_environment(container.get("environment", [])) != source.environment_sha256
                or observed_secrets != source.secret_bindings
            ):
                raise ValueError("Registered ECS container definition changed")
            return True
        except Exception:  # noqa: BLE001 -- provider diagnostics stay private
            raise RuntimeError("Registered source application runtime unavailable") from None

    def _target(self):
        r = self.registration.target
        try:
            daemon = strict_external_json(
                self.vm_command(["info", "--format", "{{json .ID}}"]),
                maximum=128 * 1024,
                expected_type=str,
            )
            containers = strict_external_json(
                self.vm_command(["inspect", r.container_id]),
                maximum=128 * 1024,
                expected_type=list,
            )
            if len(containers) != 1 or not isinstance(containers[0], dict):
                raise ValueError("Exact VM application inspection required")
            (container,) = containers
            labels = container.get("Config", {}).get("Labels", {})
            mounts = container.get("Mounts", [])
            networks = container.get("NetworkSettings", {}).get("Networks", {})
            if (
                daemon != r.daemon_id
                or container.get("Id") != r.container_id
                or container.get("Image") != r.image_id
                or container.get("State", {}).get("Running") is not True
                or container.get("HostConfig", {}).get("ReadonlyRootfs") is not True
                or container.get("HostConfig", {}).get("Privileged") is not False
                or container.get("HostConfig", {}).get("NetworkMode") != r.network_name
                or set(networks) != {r.network_name}
                or container.get("Config", {}).get("User") != r.user
                or _docker_environment(container.get("Config", {}).get("Env", [])) != r.environment_sha256
                or any(labels.get(key) != value for key, value in r.required_labels)
                or len(mounts) != 1
                or mounts[0].get("Type") != "volume"
                or mounts[0].get("Name") != r.config_volume
                or mounts[0].get("Destination") != r.config_destination
                or mounts[0].get("RW") is not False
            ):
                raise ValueError("Registered VM application identity changed")
            return True
        except Exception:  # noqa: BLE001 -- SSH/Docker diagnostics stay private
            raise RuntimeError("Registered target application runtime unavailable") from None

    def __call__(self, binding):
        if binding == asdict(self.registration.transfer.source):
            return self._source()
        if binding == asdict(self.registration.transfer.target):
            return self._target()
        raise ValueError("Application runtime binding differs from registered transfer")
