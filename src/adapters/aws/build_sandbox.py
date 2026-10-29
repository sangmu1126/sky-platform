"""One-use credential-free VM with an independently enforced AWS deadline.

Only a registered control-plane caller may invoke this adapter. It does not
claim to be a GitHub build, issue application approvals, or execute user source
in the controller. Native AWS outages can delay the external termination.
"""

import base64
import re
from datetime import UTC, datetime, timedelta
from uuid import UUID

from botocore.config import Config

BOOTSTRAP = """#!/bin/bash
set -eu
systemctl disable --now ecs || true
mkdir -p /etc/systemd/system/sky-build.slice.d /etc/docker
printf '[Slice]\\nCPUQuota=200%%\\nMemoryMax=1536M\\nTasksMax=256\\n' > /etc/systemd/system/sky-build.slice.d/limits.conf
printf '{"cgroup-parent":"sky-build.slice","live-restore":false,"log-driver":"local","log-opts":{"max-size":"8m","max-file":"2"}}' > /etc/docker/daemon.json
systemctl daemon-reload
systemctl restart docker
ssh-keygen -A
read -r keytype keybody ignored < /etc/ssh/ssh_host_ed25519_key.pub
printf 'SKY_HOST_KEY=%s %s\\n' "$keytype" "$keybody" > /dev/console
"""


class AwsBuildSandbox:
    def __init__(self, profile, session, guard, *, now=lambda: datetime.now(UTC)):
        if not callable(guard):
            raise ValueError("Current authorization/lease guard is required")
        self.profile, self.guard, self.now = profile, guard, now
        config = Config(connect_timeout=5, read_timeout=15, retries={"total_max_attempts": 1})
        self.ec2 = session.client("ec2", region_name=profile.region, config=config)
        self.sts = session.client("sts", region_name=profile.region, config=config)
        self.scheduler = session.client("scheduler", region_name=profile.region, config=config)

    def call(self, client, operation, **kwargs):
        self.guard()
        result = getattr(client, operation)(**kwargs)
        self.guard()
        return result

    def launch(self, job_id, public_key, *, lifetime=None):
        if not isinstance(job_id, str) or str(UUID(job_id)) != job_id:
            raise ValueError("Canonical one-use job identity required")
        if (
            not isinstance(public_key, str)
            or len(public_key) > 1024
            or not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]+=*(?: [A-Za-z0-9_.@-]+)?\n?", public_key)
        ):
            raise ValueError("Ephemeral Ed25519 public key required")
        p = self.profile
        lifetime = p.max_lifetime_seconds if lifetime is None else lifetime
        if type(lifetime) is not int or not 180 <= lifetime <= p.max_lifetime_seconds:
            raise ValueError("Build lifetime exceeds registration")
        if self.call(self.sts, "get_caller_identity").get("Account") != p.account_id:
            raise ValueError("Sandbox account differs")
        self.guard()
        p.verify_network(self.ec2)
        self.guard()
        expiration = (self.now() + timedelta(seconds=lifetime)).replace(microsecond=0)
        name = "job-" + job_id
        # The independent deadline exists BEFORE any billable VM. No blind retries
        # after an uncertain create/run. Reconcile by the same job/client token.
        self.call(
            self.scheduler,
            "create_schedule",
            Name=name,
            GroupName=p.scheduler_group,
            ClientToken=job_id,
            ScheduleExpression=f"at({expiration.strftime('%Y-%m-%dT%H:%M:%S')})",
            ScheduleExpressionTimezone="UTC",
            FlexibleTimeWindow={"Mode": "OFF"},
            ActionAfterCompletion="DELETE",
            Target={
                "Arn": p.reaper_arn,
                "RoleArn": p.scheduler_role_arn,
                "Input": '{"job_id":"' + job_id + '"}',
                "RetryPolicy": {"MaximumEventAgeInSeconds": 300, "MaximumRetryAttempts": 2},
            },
        )
        key_name = p.name + "-" + job_id
        self.call(
            self.ec2,
            "import_key_pair",
            KeyName=key_name,
            PublicKeyMaterial=public_key.encode(),
            TagSpecifications=[
                {
                    "ResourceType": "key-pair",
                    "Tags": [
                        {"Key": "app", "Value": "sky"},
                        {"Key": "sky:JobId", "Value": job_id},
                        {"Key": "sky:SandboxProfile", "Value": p.name},
                    ],
                }
            ],
        )
        tags = [
            {"Key": "app", "Value": "sky"},
            {"Key": "sky:SandboxProfile", "Value": p.name},
            {"Key": "sky:JobId", "Value": job_id},
            {"Key": "sky:DeadlineEpoch", "Value": str(int(expiration.timestamp()))},
        ]
        try:
            response = self.call(
                self.ec2,
                "run_instances",
                ImageId=p.ami_id,
                InstanceType="t3.small",
                MinCount=1,
                MaxCount=1,
                ClientToken=job_id,
                KeyName=key_name,
                NetworkInterfaces=[
                    {
                        "DeviceIndex": 0,
                        "SubnetId": p.subnet_id,
                        "Groups": [p.security_group_id],
                        "AssociatePublicIpAddress": True,
                        "DeleteOnTermination": True,
                    }
                ],
                # Trusted cloud-init needs metadata for the temporary SSH key.
                # There is no instance role. Seal before transferring any source.
                MetadataOptions={
                    "HttpEndpoint": "enabled",
                    "HttpTokens": "required",
                    "HttpPutResponseHopLimit": 1,
                },
                CreditSpecification={"CpuCredits": "standard"},
                BlockDeviceMappings=[
                    {
                        "DeviceName": "/dev/xvda",
                        "Ebs": {
                            "VolumeSize": 30,
                            "VolumeType": "gp3",
                            "Encrypted": True,
                            "DeleteOnTermination": True,
                        },
                    }
                ],
                TagSpecifications=[
                    {"ResourceType": kind, "Tags": tags}
                    for kind in ("instance", "volume", "network-interface")
                ],
                InstanceInitiatedShutdownBehavior="terminate",
                UserData=BOOTSTRAP,
            )
        except Exception:
            # Leave the independent deadline active: RunInstances may have succeeded.
            raise
        instances = response.get("Instances", [])
        if len(instances) != 1:
            raise ValueError("Uncertain sandbox launch; reconcile by job tag")
        instance = instances[0]
        self._scope(instance, job_id, bootstrapping=True)
        return {
            "job_id": job_id,
            "instance_id": instance["InstanceId"],
            "key_name": key_name,
            "expires_at": expiration.isoformat(),
            "profile": p.name,
            "account_id": p.account_id,
            "region": p.region,
            "credentials_in_guest": False,
            "outbound_security_group_rules": 0,
            "source_transfer_allowed": False,
        }

    def _scope(self, instance, job_id, *, bootstrapping=False):
        tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
        if (
            tags.get("sky:JobId") != job_id
            or tags.get("app") != "sky"
            or tags.get("sky:SandboxProfile") != self.profile.name
        ):
            raise ValueError("Guest immutable owner/job tags differ")
        # EC2 discards VPC/group information after termination. Account, exact
        # instance ID and job tags remain authoritative for cleanup confirmation.
        if instance.get("State", {}).get("Name") == "terminated" or (
            bootstrapping and instance.get("State", {}).get("Name") == "shutting-down"
        ):
            return
        if (
            instance.get("VpcId") != self.profile.vpc_id
            or {g["GroupId"] for g in instance.get("SecurityGroups", [])} != {self.profile.security_group_id}
            or tags.get("sky:JobId") != job_id
            or tags.get("app") != "sky"
            or tags.get("sky:SandboxProfile") != self.profile.name
            or instance.get("IamInstanceProfile")
            or (
                not bootstrapping
                and (
                    instance.get("MetadataOptions", {}).get("HttpEndpoint") != "disabled"
                    or instance.get("MetadataOptions", {}).get("State") != "applied"
                )
            )
        ):
            raise ValueError("Guest identity, credential or network boundary differs")

    def inspect(self, receipt, *, bootstrapping=False):
        p = self.profile
        if any(
            receipt.get(k) != v
            for k, v in (("profile", p.name), ("account_id", p.account_id), ("region", p.region))
        ):
            raise ValueError("Sandbox receipt registration mismatch")
        reservations = self.call(self.ec2, "describe_instances", InstanceIds=[receipt["instance_id"]])[
            "Reservations"
        ]
        if (
            len(reservations) != 1
            or reservations[0].get("OwnerId") != p.account_id
            or len(reservations[0]["Instances"]) != 1
        ):
            raise ValueError("Sandbox account/instance observation mismatch")
        instance = reservations[0]["Instances"][0]
        self._scope(instance, receipt["job_id"], bootstrapping=bootstrapping)
        return instance

    def host_key(self, receipt):
        self.inspect(receipt, bootstrapping=True)
        output = self.call(
            self.ec2, "get_console_output", InstanceId=receipt["instance_id"], Latest=True
        ).get("Output", "")
        if "SKY_HOST_KEY=" not in output:
            try:
                output = base64.b64decode(output, validate=True).decode("utf-8", errors="replace")
            except (ValueError, UnicodeError):
                return None
        keys = re.findall(r"SKY_HOST_KEY=(ssh-ed25519 [A-Za-z0-9+/]+=*)", output)
        if not keys and "SKY_HOST_KEY=" in output and "-----END SSH HOST KEY KEYS-----" in output:
            # Older bootstrap writes can interleave with console messages.
            # Only the authenticated EC2 boot console is read, before source.
            keys = re.findall(r"(?m)^(ssh-ed25519 [A-Za-z0-9+/]+=*)", output)
        if not keys:
            return None
        if len(set(keys)) != 1:
            raise ValueError("Ambiguous trusted boot host key")
        return keys[0]

    def seal(self, receipt):
        if self.host_key(receipt) is None:
            raise ValueError("Trusted bootstrap is not ready; source transfer forbidden")
        self.call(
            self.ec2,
            "modify_instance_metadata_options",
            InstanceId=receipt["instance_id"],
            HttpEndpoint="disabled",
            HttpTokens="required",
            HttpPutResponseHopLimit=1,
        )
        return {"metadata_disable_requested": True, "source_transfer_allowed": False}

    def terminate(self, receipt):
        instance = self.inspect(receipt, bootstrapping=True)
        if instance["State"]["Name"] != "terminated":
            self.call(self.ec2, "terminate_instances", InstanceIds=[receipt["instance_id"]])
        # Confirmation and key deletion are separate: never imply termination from
        # request acceptance, or delete the deadline before observing termination.
        return {"termination_requested": True, "instance_id": receipt["instance_id"]}

    def finalize(self, receipt):
        if self.inspect(receipt, bootstrapping=True)["State"]["Name"] != "terminated":
            raise ValueError("Sandbox has not terminated; keep deadline and reconciliation record")
        self.call(self.ec2, "delete_key_pair", KeyName=self.profile.name + "-" + receipt["job_id"])
        return {"termination_confirmed": True, "instance_id": receipt["instance_id"]}
