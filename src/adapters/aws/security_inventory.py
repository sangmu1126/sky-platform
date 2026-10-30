"""Read-only, operator-registered AWS evidence; uploaded reports have no authority."""

import hashlib
import ipaddress
import json
import math
import re
from datetime import datetime, timedelta
from uuid import NAMESPACE_URL, uuid5


def fingerprint(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(raw) > 262144:
        raise ValueError("Security inventory exceeds its evidence bound")
    return hashlib.sha256(raw).hexdigest()


def report(kind, identity, facts, now, *, complete=True, matched=False):
    evidence = fingerprint(facts)
    return {
        "version": 1,
        "collection_complete": complete,
        "absence_of_compromise_proven": False,
        "facts_digest": evidence,
        "events": (
            [
                {
                    "kind": kind,
                    "event_id": str(uuid5(NAMESPACE_URL, identity + ":" + evidence)),
                    "observed_at": now,
                    "evidence_digest": evidence,
                }
            ]
            if matched
            else []
        ),
    }


class NativeSecurityInventory:
    def __init__(self, account_id, region, *, session):
        if not re.fullmatch(r"[0-9]{12}", account_id) or not re.fullmatch(
            r"[a-z]{2}(?:-[a-z]+)+-\d+", region
        ):
            raise ValueError("Exact native evidence account and region required")
        from botocore.config import Config

        config = Config(connect_timeout=5, read_timeout=15, retries={"total_max_attempts": 1})
        self.account, self.region = account_id, region
        self.clients = {
            name: session.client(name, region_name=region, config=config)
            for name in ("sts", "iam", "ecs", "rds", "cloudwatch", "ec2", "logs")
        }

    def check(self, now):
        stamp = datetime.fromisoformat(now)
        if stamp.tzinfo is None or self.clients["sts"].get_caller_identity().get("Account") != self.account:
            raise ValueError("Authenticated current native evidence account required")
        return stamp

    def iam_snapshot(self, registration):
        if not isinstance(registration, dict) or set(registration) != {
            "role_arn",
            "role_id",
            "expected_digest",
        }:
            raise ValueError("Exact role snapshot registration required")
        arn = registration["role_arn"]
        if (
            not re.fullmatch(rf"arn:aws:iam::{self.account}:role/sky-[A-Za-z0-9_-]+", arn)
            or not re.fullmatch(r"AROA[A-Z0-9]{17}", registration["role_id"])
            or not re.fullmatch(r"[0-9a-f]{64}", registration["expected_digest"])
        ):
            raise ValueError("Pinned owned role incarnation and policy digest required")
        iam, name = self.clients["iam"], arn.rsplit("/", 1)[1]
        role = iam.get_role(RoleName=name)["Role"]
        if role.get("Arn") != arn:
            raise ValueError("IAM snapshot belongs to another role")
        inline = iam.list_role_policies(RoleName=name, MaxItems=17)
        attached = iam.list_attached_role_policies(RoleName=name, MaxItems=17)
        if (
            inline.get("IsTruncated")
            or attached.get("IsTruncated")
            or len(inline.get("PolicyNames", [])) > 16
            or len(attached.get("AttachedPolicies", [])) > 16
        ):
            raise ValueError("IAM snapshot incomplete or exceeds bound")
        docs = {}
        for key in sorted(inline["PolicyNames"]):
            docs["inline:" + key] = iam.get_role_policy(RoleName=name, PolicyName=key)["PolicyDocument"]
        for item in sorted(attached["AttachedPolicies"], key=lambda x: x["PolicyArn"]):
            policy = iam.get_policy(PolicyArn=item["PolicyArn"])["Policy"]
            if policy.get("Arn") != item["PolicyArn"]:
                raise ValueError("IAM attached policy identity changed")
            version = iam.get_policy_version(
                PolicyArn=item["PolicyArn"], VersionId=policy["DefaultVersionId"]
            )["PolicyVersion"]
            if (
                version.get("VersionId") != policy["DefaultVersionId"]
                or version.get("IsDefaultVersion") is not True
            ):
                raise ValueError("IAM policy version changed during collection")
            docs["managed:" + item["PolicyArn"]] = version["Document"]
        return {
            "role_arn": arn,
            "role_id": role.get("RoleId"),
            "trust": role["AssumeRolePolicyDocument"],
            "boundary": role.get("PermissionsBoundary"),
            "policies": docs,
        }

    def observe_iam(self, registration, *, now):
        self.check(now)
        snapshot = self.iam_snapshot(registration)
        return report(
            "unapproved_iam_change",
            registration["role_arn"],
            snapshot,
            now,
            matched=snapshot["role_id"] != registration["role_id"]
            or fingerprint(snapshot) != registration["expected_digest"],
        )

    def observe_image(self, registration, *, now):
        self.check(now)
        if not isinstance(registration, dict) or set(registration) != {
            "service_arn",
            "task_definition_arn",
            "container",
            "image",
        }:
            raise ValueError("Exact service image registration required")
        prefix = f"arn:aws:ecs:{self.region}:{self.account}:"
        arn = registration["service_arn"]
        match = re.fullmatch(re.escape(prefix) + r"service/([A-Za-z0-9_-]+)/([A-Za-z0-9_-]+)", arn)
        if (
            not match
            or not re.fullmatch(
                re.escape(prefix) + r"task-definition/[A-Za-z0-9_-]+:[1-9][0-9]*",
                registration["task_definition_arn"],
            )
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", registration["container"])
            or not re.fullmatch(
                rf"{self.account}\.dkr\.ecr\.{self.region}\.amazonaws\.com/[a-z0-9/_-]+@sha256:[0-9a-f]{{64}}",
                registration["image"],
            )
        ):
            raise ValueError("Pinned service/task/image required")
        cluster, name = match.groups()
        ecs = self.clients["ecs"]
        services = ecs.describe_services(cluster=cluster, services=[arn])
        if (
            services.get("failures")
            or len(services.get("services", [])) != 1
            or services["services"][0].get("serviceArn") != arn
        ):
            raise ValueError("Exact service inventory unavailable")
        listed = ecs.list_tasks(cluster=cluster, serviceName=name, desiredStatus="RUNNING", maxResults=10)
        arns = listed.get("taskArns", [])
        if (
            listed.get("nextToken")
            or not isinstance(arns, list)
            or len(arns) > 10
            or len(set(arns)) != len(arns)
            or any(not isinstance(a, str) or not a.startswith(prefix + "task/" + cluster + "/") for a in arns)
        ):
            raise ValueError("Service task inventory incomplete")
        if not arns:
            return report("artifact_identity_mismatch", arn, {"tasks": []}, now, complete=False)
        response = ecs.describe_tasks(cluster=cluster, tasks=arns)
        tasks = response.get("tasks", [])
        if (
            response.get("failures")
            or {t.get("taskArn") for t in tasks} != set(arns)
            or len(tasks) != len(arns)
        ):
            raise ValueError("Exact service task inventory unavailable")
        facts = []
        mismatch = services["services"][0].get("taskDefinition") != registration["task_definition_arn"]
        for task in tasks:
            if task.get("group") != "service:" + name or task.get("lastStatus") != "RUNNING":
                raise ValueError("Task ownership or running state changed")
            containers = [c for c in task.get("containers", []) if c.get("name") == registration["container"]]
            if len(containers) != 1:
                raise ValueError("Registered image container unavailable")
            c = containers[0]
            facts.append(
                {
                    "task": task["taskArn"],
                    "definition": task.get("taskDefinitionArn"),
                    "image": c.get("image"),
                    "digest": c.get("imageDigest"),
                }
            )
            mismatch |= (
                task.get("taskDefinitionArn") != registration["task_definition_arn"]
                or c.get("image") != registration["image"]
                or c.get("imageDigest") != registration["image"].split("@")[1]
            )
        return report(
            "artifact_identity_mismatch", arn, sorted(facts, key=lambda x: x["task"]), now, matched=mismatch
        )

    def observe_capacity(self, registration, *, now):
        stamp = self.check(now)
        if not isinstance(registration, dict) or set(registration) != {
            "instance_id",
            "resource_id",
            "connection_threshold",
            "free_storage_threshold_bytes",
        }:
            raise ValueError("Exact RDS capacity registration required")
        name = registration["instance_id"]
        if (
            not re.fullmatch(r"sky-[a-z0-9-]{1,60}", name)
            or not re.fullmatch(r"db-[A-Z0-9]{1,64}", registration["resource_id"])
            or any(
                type(registration[k]) is not int or registration[k] <= 0
                for k in ("connection_threshold", "free_storage_threshold_bytes")
            )
        ):
            raise ValueError("Pinned RDS identity and positive capacity thresholds required")
        instances = self.clients["rds"].describe_db_instances(DBInstanceIdentifier=name)["DBInstances"]
        arn = f"arn:aws:rds:{self.region}:{self.account}:db:{name}"
        if (
            len(instances) != 1
            or instances[0].get("DBInstanceArn") != arn
            or instances[0].get("DbiResourceId") != registration["resource_id"]
        ):
            raise ValueError("RDS incarnation differs from registration")
        facts = {}
        matched = False
        complete = True
        for metric, stat, threshold, above in [
            ("DatabaseConnections", "Maximum", registration["connection_threshold"], True),
            ("FreeStorageSpace", "Minimum", registration["free_storage_threshold_bytes"], False),
        ]:
            value = self.clients["cloudwatch"].get_metric_statistics(
                Namespace="AWS/RDS",
                MetricName=metric,
                Dimensions=[{"Name": "DBInstanceIdentifier", "Value": name}],
                StartTime=stamp - timedelta(minutes=5),
                EndTime=stamp,
                Period=60,
                Statistics=[stat],
            )
            samples = []
            for point in value.get("Datapoints", []):
                t, n = point.get("Timestamp"), point.get(stat)
                if (
                    not isinstance(t, datetime)
                    or t.tzinfo is None
                    or not stamp - timedelta(minutes=4) <= t <= stamp
                    or not isinstance(n, (float, int))
                    or isinstance(n, bool)
                    or not math.isfinite(n)
                    or n < 0
                ):
                    raise ValueError("Stale, future or malformed RDS metric sample")
                samples.append((t, n))
            samples = sorted(samples)
            if len(samples) < 2 or len({x[0] for x in samples}) != len(samples):
                complete = False
            else:
                matched |= all(n >= threshold if above else n <= threshold for _, n in samples[-2:])
            facts[metric] = [(t.isoformat(), n) for t, n in samples]
        return report("database_capacity_exhausted", arn, facts, now, complete=complete, matched=matched)

    def observe_flow(self, registration, *, now):
        stamp = self.check(now)
        if not isinstance(registration, dict) or set(registration) != {
            "flow_log_id",
            "interface_id",
            "vpc_id",
            "log_group",
            "allowed_destinations",
        }:
            raise ValueError("Exact Flow Logs registration required")
        for key, pattern in [
            ("flow_log_id", r"fl-[0-9a-f]{8,17}"),
            ("interface_id", r"eni-[0-9a-f]{8,17}"),
            ("vpc_id", r"vpc-[0-9a-f]{8,17}"),
            ("log_group", r"/sky/[A-Za-z0-9/_-]{1,200}"),
        ]:
            if not isinstance(registration[key], str) or not re.fullmatch(pattern, registration[key]):
                raise ValueError("Exact owned Flow Logs identity required")
        raw = registration["allowed_destinations"]
        if not isinstance(raw, list) or len(raw) > 32:
            raise ValueError("Bounded operator egress allow-list required")
        allowed = [ipaddress.ip_network(c, strict=True) for c in raw]
        ec2 = self.clients["ec2"]
        flows = ec2.describe_flow_logs(FlowLogIds=[registration["flow_log_id"]]).get("FlowLogs", [])
        fmt = "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}"
        if len(flows) != 1 or any(
            flows[0].get(k) != v
            for k, v in {
                "FlowLogId": registration["flow_log_id"],
                "ResourceId": registration["interface_id"],
                "FlowLogStatus": "ACTIVE",
                "LogDestinationType": "cloud-watch-logs",
                "LogGroupName": registration["log_group"],
                "LogFormat": fmt,
            }.items()
        ):
            raise ValueError("Registered native Flow Logs source changed")
        enis = ec2.describe_network_interfaces(NetworkInterfaceIds=[registration["interface_id"]]).get(
            "NetworkInterfaces", []
        )
        if (
            len(enis) != 1
            or enis[0].get("OwnerId") != self.account
            or enis[0].get("VpcId") != registration["vpc_id"]
        ):
            raise ValueError("Flow Logs interface ownership changed")
        token = None
        events = []
        seen = set()
        complete = True
        for _ in range(3):
            args = {
                "logGroupName": registration["log_group"],
                "startTime": int((stamp - timedelta(minutes=15)).timestamp() * 1000),
                "endTime": int(stamp.timestamp() * 1000),
                "limit": 50,
            }
            if token:
                args["nextToken"] = token
            response = self.clients["logs"].filter_log_events(**args)
            records = response.get("events", [])
            if not isinstance(records, list) or len(records) > 50:
                raise ValueError("Bounded native flow evidence required")
            for item in records:
                identity = item.get("eventId")
                message = item.get("message")
                if (
                    not isinstance(identity, str)
                    or len(identity) > 512
                    or not isinstance(message, str)
                    or len(message) > 2048
                ):
                    raise ValueError("Bounded native flow record required")
                if identity in seen:
                    continue
                seen.add(identity)
                parts = message.split()
                if len(parts) != 14 or parts[1] != self.account or parts[2] != registration["interface_id"]:
                    continue
                if parts[13] != "OK":
                    complete = False
                    continue
                end = datetime.fromtimestamp(int(parts[11]), tz=stamp.tzinfo)
                if not stamp - timedelta(minutes=15) <= end <= stamp:
                    raise ValueError("Flow record outside collection window")
                target = ipaddress.ip_address(parts[4])
                source = ipaddress.ip_address(parts[3])
                if str(source) != enis[0].get("PrivateIpAddress"):
                    continue  # Inbound traffic is not outbound exfiltration.
                if not any(target.version == net.version and target in net for net in allowed):
                    kind = {"ACCEPT": "forbidden_network_egress", "REJECT": "blocked_network_egress"}.get(
                        parts[12]
                    )
                    if kind:
                        events.append(
                            {
                                "kind": kind,
                                "event_id": str(
                                    uuid5(NAMESPACE_URL, registration["flow_log_id"] + ":" + identity)
                                ),
                                "observed_at": end.isoformat(),
                                "evidence_digest": fingerprint(parts),
                            }
                        )
            token = response.get("nextToken")
            if not token:
                break
            if not isinstance(token, str) or len(token) > 4096:
                raise ValueError("Invalid flow continuation")
        return {
            "version": 1,
            "collection_complete": complete and not bool(token),
            "absence_of_compromise_proven": False,
            "events": events,
        }
