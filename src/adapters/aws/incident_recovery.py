"""Restricted standard-Fargate recovery of a registered PostgreSQL HTTP image.

Fresh pre-registered roles are required: a deny-all app task role and one exact
execution policy. The private candidate Secret is never exposed to the runtime.
Activation publishes a pinned new version of the original owned app Secret,
retaining its denial for all old runtime role incarnations.
"""

import ipaddress
import json
import re
import time
import urllib.request
from copy import deepcopy
from dataclasses import asdict

from adapters.github.remote_build import NoRedirect
from domain.incident_recovery import RecoveryRuntimeRegistration


class AwsIncidentRecovery:
    def __init__(self, registration, verification, *, clock, session=None, probe=None, wait=None):
        if not isinstance(registration, RecoveryRuntimeRegistration):
            raise TypeError("Trusted recovery runtime registration required")
        import boto3
        from botocore.config import Config

        self.r, self.verification, self.clock = registration, verification, clock
        session = session or boto3.Session(region_name=registration.region)
        config = Config(retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=15)
        self.clients = {
            name: session.client(name, region_name=registration.region, config=config)
            for name in ("ecs", "ec2", "iam", "sts", "secretsmanager")
        }
        self.probe = probe or self.http_probe
        self.wait = wait or time.sleep

    @staticmethod
    def http_probe(url):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(url, timeout=5) as response:
            if response.status != 200:
                raise ValueError("Recovery HTTP probe failed")

    def execution_policy(self, image, secret, key):
        r = self.r
        prefix = f"{r.account_id}.dkr.ecr.{r.region}.amazonaws.com/"
        if not image.startswith(prefix) or not re.fullmatch(
            r"[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}", image[len(prefix) :]
        ):
            raise ValueError("Registered same-account ECR image required")
        repository = image[len(prefix) :].split("@")[0]
        return {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["ecr:GetAuthorizationToken"], "Resource": "*"},
                {
                    "Effect": "Allow",
                    "Action": [
                        "ecr:BatchCheckLayerAvailability",
                        "ecr:GetDownloadUrlForLayer",
                        "ecr:BatchGetImage",
                    ],
                    "Resource": f"arn:aws:ecr:{r.region}:{r.account_id}:repository/{repository}",
                },
                {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": secret},
                {
                    "Effect": "Allow",
                    "Action": ["kms:Decrypt"],
                    "Resource": key,
                    "Condition": {
                        "StringEquals": {
                            "kms:ViaService": f"secretsmanager.{r.region}.amazonaws.com",
                            "kms:EncryptionContext:SecretARN": secret,
                        }
                    },
                },
            ],
        }

    def _call(self, name, method, guard, **kw):
        guard()
        result = getattr(self.clients[name], method)(**kw)
        guard()
        return result

    def preflight(self, job, recovery_id, *, guard):
        from application.incident_secret_access import access_context

        r = self.r
        context = access_context(job, self.verification.registration)
        if (
            job.get("organization_id"),
            job.get("application_id"),
            job.get("id"),
            context["binding"]["account_id"],
            context["binding"]["region"],
            recovery_id,
        ) != (r.organization_id, r.application_id, r.job_id, r.account_id, r.region, r.recovery_id) or (
            job["security_hold"]["incident_id"],
            job["security_review_boundary"]["id"],
        ) != (r.incident_id, r.boundary_id):
            raise ValueError("Recovery registration differs from held deployment")
        if self._call("sts", "get_caller_identity", guard).get("Account") != r.account_id:
            raise ValueError("Recovery account changed")
        image = job["security_artifact_review"]["binding"]["image"]
        policy = self.execution_policy(image, context["secret_arn"], context["kms_key_arn"])
        tags = {"sky-managed": "true", "sky-recovery-id": r.recovery_id}
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": r.account_id},
                        "ArnLike": {"aws:SourceArn": f"arn:aws:ecs:{r.region}:{r.account_id}:*"},
                    },
                }
            ],
        }
        old_roles = job["security_secret_access_fence"]["target"]["roles"]
        # This profile cannot revoke arbitrary exfiltrated AWS credentials.
        # Admit only old roles whose identity policies have no launch/write or
        # unrelated secret capabilities. Wider roles need separate IAM recovery.
        for arn, role_id in old_roles.items():
            name = arn.rsplit("/", 1)[-1]
            old_role = self._call("iam", "get_role", guard, RoleName=name)["Role"]
            attached = self._call("iam", "list_attached_role_policies", guard, RoleName=name)
            inline = self._call("iam", "list_role_policies", guard, RoleName=name)
            if (
                old_role.get("Arn") != arn
                or old_role.get("RoleId") != role_id
                or attached.get("IsTruncated")
                or attached.get("AttachedPolicies") != []
                or inline.get("IsTruncated")
                or len(inline.get("PolicyNames", [])) > 1
            ):
                raise ValueError("Old runtime AWS capabilities exceed the registered recovery profile")
            for policy_name in inline.get("PolicyNames", []):
                existing_policy = self._call(
                    "iam", "get_role_policy", guard, RoleName=name, PolicyName=policy_name
                )["PolicyDocument"]
                if not old_policy_within_profile(existing_policy, policy):
                    raise ValueError(
                        "Old runtime requires separate IAM credential revocation before recovery"
                    )
        for arn, rid, execution in [
            (r.execution_role_arn, r.execution_role_id, True),
            (r.task_role_arn, r.task_role_id, False),
        ]:
            if arn in old_roles:
                raise ValueError("Fresh recovery roles must differ from old runtime roles")
            name = arn.rsplit("/", 1)[-1]
            role = self._call("iam", "get_role", guard, RoleName=name)["Role"]
            if (
                role.get("Arn") != arn
                or role.get("RoleId") != rid
                or role.get("AssumeRolePolicyDocument") != trust
                or any(
                    {t["Key"]: t["Value"] for t in role.get("Tags", [])}.get(k) != v for k, v in tags.items()
                )
            ):
                raise ValueError("Recovery role incarnation, trust or ownership differs")
            attached = self._call("iam", "list_attached_role_policies", guard, RoleName=name)
            inline = self._call("iam", "list_role_policies", guard, RoleName=name)
            if (
                attached.get("IsTruncated")
                or attached.get("AttachedPolicies") != []
                or inline.get("IsTruncated")
                or inline.get("PolicyNames")
                != (["SkyIncidentRecoveryExecution"] if execution else ["SkyIncidentRecoveryNoAwsAccess"])
            ):
                raise ValueError("Recovery task must be unprivileged and execution role narrowly scoped")
            if (
                execution
                and self._call(
                    "iam", "get_role_policy", guard, RoleName=name, PolicyName="SkyIncidentRecoveryExecution"
                )["PolicyDocument"]
                != policy
            ):
                raise ValueError("Recovery execution role policy differs from registered minimum")
            if not execution and self._call(
                "iam", "get_role_policy", guard, RoleName=name, PolicyName="SkyIncidentRecoveryNoAwsAccess"
            )["PolicyDocument"] != {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
            }:
                raise ValueError("Recovery application task role must explicitly deny AWS access")
        clusters = self._call("ecs", "describe_clusters", guard, clusters=[r.cluster_arn], include=["TAGS"])
        if clusters.get("failures") or len(clusters.get("clusters", [])) != 1:
            raise ValueError("Registered recovery cluster unavailable")
        cluster = clusters["clusters"][0]
        if (
            cluster.get("clusterArn") != r.cluster_arn
            or cluster.get("status") != "ACTIVE"
            or any(
                {t["key"]: t["value"] for t in cluster.get("tags", [])}.get(k) != v for k, v in tags.items()
            )
        ):
            raise ValueError("Recovery cluster ownership differs")
        subnets = self._call("ec2", "describe_subnets", guard, SubnetIds=list(r.subnets))
        if (
            subnets.get("NextToken")
            or len(subnets.get("Subnets", [])) != len(r.subnets)
            or {s["SubnetId"] for s in subnets["Subnets"]} != set(r.subnets)
            or any(
                s.get("VpcId") != r.vpc_id
                or s.get("OwnerId") != r.account_id
                or s.get("State") != "available"
                for s in subnets["Subnets"]
            )
        ):
            raise ValueError("Registered recovery subnet scope differs")
        groups = self._call("ec2", "describe_security_groups", guard, GroupIds=[r.security_group])
        if len(groups.get("SecurityGroups", [])) != 1 or groups.get("NextToken"):
            raise ValueError("Exact recovery security group required")
        group = groups["SecurityGroups"][0]
        if (
            group.get("GroupId") != r.security_group
            or group.get("VpcId") != r.vpc_id
            or group.get("OwnerId") != r.account_id
            or any({t["Key"]: t["Value"] for t in group.get("Tags", [])}.get(k) != v for k, v in tags.items())
        ):
            raise ValueError("Recovery security group ownership differs")
        for rule in group.get("IpPermissions", []):
            if (
                rule.get("IpProtocol") != "tcp"
                or rule.get("FromPort") != r.port
                or rule.get("ToPort") != r.port
                or rule.get("Ipv6Ranges")
                or rule.get("PrefixListIds")
            ):
                raise ValueError("Only reviewed HTTP ingress is supported")
            for cidr in rule.get("IpRanges", []):
                if not r.assign_public_ip or ipaddress.ip_network(cidr["CidrIp"]).prefixlen != 32:
                    raise ValueError(
                        "Public validation access must be a single registered operator IPv4 address"
                    )
            if any(pair.get("UserId") != r.account_id for pair in rule.get("UserIdGroupPairs", [])):
                raise ValueError("Recovery ingress must remain in the registered account")
        # Inspect the actual PostgreSQL transport before it is used for activation.
        with self.verification.sql.workload_connect() as db:
            if (
                db.execute("SELECT current_database()").fetchone() != (context["binding"]["database_name"],)
                or db.info.host != r.database_host
                or not db.pgconn.ssl_in_use
            ):
                raise ValueError("Recovery workload endpoint must match the audited TLS transport")
        guard()
        return {
            "version": 1,
            "id": r.recovery_id,
            "registration": r.document(),
            "image": image,
            "context": context,
            "candidate_version_id": context["candidate_version_id"],
            "baseline_fingerprint": job["security_database_verification"]["baseline_fingerprint"],
            "old_policy_target": deepcopy(job["security_secret_access_fence"]["target"]),
            "configuration_profile": "stateless-postgres-http-v1",
            "network_policy": {
                "ingress": sorted(
                    group.get("IpPermissions", []), key=lambda value: json.dumps(value, sort_keys=True)
                ),
                "egress": sorted(
                    group.get("IpPermissionsEgress", []), key=lambda value: json.dumps(value, sort_keys=True)
                ),
            },
        }

    def activate(self, plan, *, guard):
        from adapters.database.incident_verification import database_fingerprint

        r = self.r
        p = self.verification.preparation
        context = plan["context"]
        if plan["registration"] != r.document() or plan["id"] != r.recovery_id:
            raise ValueError("Approved recovery registration changed")
        access = self.verification.secret_access.inspect(context, plan["old_policy_target"], guard=guard)
        if (
            access.get("policy_state") != "runtime_roles_denied"
            or access.get("candidate_protected") is not True
        ):
            raise ValueError("Existing role denial and private candidate must remain in force")
        observation = p.inspect(context["candidate_version_id"], guard=guard)
        if (
            observation["candidate_state"] != "registered_candidate"
            or observation["login_enabled"] is not False
            or observation["active_sessions"] != 0
        ):
            raise ValueError("Isolated restricted candidate required before activation")
        with self.verification.sql.workload_connect() as db:
            db.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            if database_fingerprint(db, p.binding) != plan["baseline_fingerprint"]:
                raise ValueError("Reviewed workload baseline changed before activation")
        guard()
        candidate = self._call(
            "secretsmanager",
            "get_secret_value",
            guard,
            SecretId=context["candidate_secret_arn"],
            VersionId=context["candidate_version_id"],
            VersionStage="AWSCURRENT",
        )
        old = self._call(
            "secretsmanager",
            "get_secret_value",
            guard,
            SecretId=context["secret_arn"],
            VersionStage="AWSCURRENT",
        )
        fresh, previous = json.loads(candidate["SecretString"]), json.loads(old["SecretString"])
        if (
            candidate.get("ARN") != context["candidate_secret_arn"]
            or candidate.get("VersionId") != context["candidate_version_id"]
            or old.get("ARN") != context["secret_arn"]
            or fresh.get("binding") != asdict(p.binding)
            or fresh.get("username") != p.restriction.fence.role
            or previous.get("username") != fresh["username"]
            or previous.get("dbname") != p.binding.database_name
            or previous.get("resource_id") != p.resource_id
        ):
            raise ValueError("Credential publication differs from registered workload")
        published = {**previous, "password": fresh["password"]}
        result = self._call(
            "secretsmanager",
            "put_secret_value",
            guard,
            SecretId=context["secret_arn"],
            ClientRequestToken=r.recovery_id,
            SecretString=json.dumps(published),
            VersionStages=["AWSCURRENT"],
        )
        if result.get("ARN") != context["secret_arn"] or result.get("VersionId") != r.recovery_id:
            raise ValueError("Credential publication outcome uncertain")
        access = self.verification.secret_access.inspect(context, plan["old_policy_target"], guard=guard)
        if (
            access.get("policy_state") != "runtime_roles_denied"
            or access.get("candidate_protected") is not True
        ):
            raise ValueError("Existing role denial and private candidate must remain in force")
        p.restriction.fence.set_login(True, guard=guard)
        guard()
        return {"version_id": r.recovery_id, "login_enabled": True, "candidate_remains_private": True}

    def deploy(self, plan, *, guard):
        r = self.r
        name = "sky-incident-" + r.recovery_id[:16]
        context = plan["context"]
        tags = [
            {"key": "sky-managed", "value": "true"},
            {"key": "sky-attempt", "value": r.recovery_id[:16]},
            {"key": "sky-recovery-id", "value": r.recovery_id},
        ]
        environment = {
            "PORT": str(r.port),
            "PGHOST": r.database_host,
            "PGPORT": "5432",
            "PGDATABASE": context["binding"]["database_name"],
            "PGSSLMODE": "verify-full",
            "PGSSLROOTCERT": "/etc/ssl/certs/sky-rds-global-bundle.pem",
        }
        container = {
            "name": "App",
            "image": plan["image"],
            "essential": True,
            "portMappings": [{"containerPort": r.port, "hostPort": r.port, "protocol": "tcp"}],
            "environment": [{"name": k, "value": v} for k, v in environment.items()],
            "secrets": [
                {"name": k, "valueFrom": context["secret_arn"] + ":" + field + "::" + r.recovery_id}
                for k, field in [("PGUSER", "username"), ("PGPASSWORD", "password")]
            ],
            "readonlyRootFilesystem": True,
            "user": "65534:65534",
            "linuxParameters": {"capabilities": {"drop": ["ALL"]}},
            "privileged": False,
        }
        definition = self._call(
            "ecs",
            "register_task_definition",
            guard,
            family=name,
            networkMode="awsvpc",
            requiresCompatibilities=["FARGATE"],
            cpu="256",
            memory="512",
            executionRoleArn=r.execution_role_arn,
            taskRoleArn=r.task_role_arn,
            containerDefinitions=[container],
            runtimePlatform={"cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX"},
            tags=tags,
        )["taskDefinition"]["taskDefinitionArn"]
        service = self._call(
            "ecs",
            "create_service",
            guard,
            cluster=r.cluster_arn,
            serviceName=name,
            taskDefinition=definition,
            desiredCount=1,
            launchType="FARGATE",
            clientToken=r.recovery_id,
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": list(r.subnets),
                    "securityGroups": [r.security_group],
                    "assignPublicIp": "ENABLED" if r.assign_public_ip else "DISABLED",
                }
            },
            tags=tags,
        )["service"]["serviceArn"]
        expected = r.cluster_arn.replace(":cluster/", ":service/") + "/" + name
        if service != expected or not definition.startswith(
            f"arn:aws:ecs:{r.region}:{r.account_id}:task-definition/{name}:"
        ):
            raise ValueError("Recovery task definition or service identity changed")
        return {"service_arn": service, "task_definition_arn": definition, "container": container}

    def verify(self, plan, submitted, *, guard):
        r = self.r
        deadline = time.monotonic() + 240
        while True:
            response = self._call(
                "ecs",
                "describe_services",
                guard,
                cluster=r.cluster_arn,
                services=[submitted["service_arn"]],
                include=["TAGS"],
            )
            if response.get("failures") or len(response.get("services", [])) != 1:
                raise ValueError("Recovery service unavailable")
            service = response["services"][0]
            if (
                service.get("serviceArn") != submitted["service_arn"]
                or service.get("taskDefinition") != submitted["task_definition_arn"]
                or {t["key"]: t["value"] for t in service.get("tags", [])}.get("sky-recovery-id")
                != r.recovery_id
            ):
                raise ValueError("Recovery service ownership changed")
            if (
                service.get("desiredCount") == service.get("runningCount") == 1
                and service.get("pendingCount") == 0
            ):
                break
            if time.monotonic() > deadline:
                raise TimeoutError("Recovery service did not become ready")
            self.wait(3)
        tasks = self._call(
            "ecs",
            "list_tasks",
            guard,
            cluster=r.cluster_arn,
            serviceName=submitted["service_arn"].rsplit("/", 1)[-1],
            desiredStatus="RUNNING",
            maxResults=100,
        )
        if tasks.get("nextToken") or len(tasks.get("taskArns", [])) != 1:
            raise ValueError("Exact one-task recovery profile required")
        observed = self._call("ecs", "describe_tasks", guard, cluster=r.cluster_arn, tasks=tasks["taskArns"])
        if observed.get("failures") or len(observed.get("tasks", [])) != 1:
            raise ValueError("Recovery task unavailable")
        task = observed["tasks"][0]
        if (
            task.get("taskDefinitionArn") != submitted["task_definition_arn"]
            or task.get("lastStatus") != "RUNNING"
            or task.get("desiredStatus") != "RUNNING"
            or len(task.get("containers", [])) != 1
            or task["containers"][0].get("imageDigest") != plan["image"].split("@")[1]
        ):
            raise ValueError("Actual recovery image differs from approval")
        definition = self._call(
            "ecs", "describe_task_definition", guard, taskDefinition=submitted["task_definition_arn"]
        )["taskDefinition"]
        containers = definition.get("containerDefinitions", [])
        if (
            len(containers) != 1
            or normalized_container(containers[0]) != normalized_container(submitted["container"])
            or definition.get("volumes")
            or definition.get("executionRoleArn") != r.execution_role_arn
            or definition.get("taskRoleArn") != r.task_role_arn
        ):
            raise ValueError("Actual recovery execution configuration differs from approval")
        ids = [
            d["value"]
            for a in task.get("attachments", [])
            for d in a.get("details", [])
            if d.get("name") == "networkInterfaceId"
        ]
        if len(ids) != 1:
            raise ValueError("Exact recovery network interface required")
        interfaces = self._call("ec2", "describe_network_interfaces", guard, NetworkInterfaceIds=ids)[
            "NetworkInterfaces"
        ]
        if len(interfaces) != 1:
            raise ValueError("Recovery interface unavailable")
        nic = interfaces[0]
        if (
            nic.get("VpcId") != r.vpc_id
            or nic.get("SubnetId") not in r.subnets
            or {g["GroupId"] for g in nic.get("Groups", [])} != {r.security_group}
        ):
            raise ValueError("Recovery network differs from registration")
        address = (
            nic.get("Association", {}).get("PublicIp") if r.assign_public_ip else nic.get("PrivateIpAddress")
        )
        ip = ipaddress.ip_address(address)
        if ip.version != 4 or (r.assign_public_ip and not ip.is_global):
            raise ValueError("Invalid recovery endpoint address")
        url = f"http://{address}:{r.port}"
        while True:
            guard()
            try:
                self.probe(url + r.health_path)
                break
            except (OSError, ValueError):
                if time.monotonic() > deadline:
                    raise OSError("Recovery HTTP endpoint did not become healthy") from None
                self.wait(2)
        guard()
        context = plan["context"]
        candidate = self._call(
            "secretsmanager",
            "get_secret_value",
            guard,
            SecretId=context["candidate_secret_arn"],
            VersionId=context["candidate_version_id"],
            VersionStage="AWSCURRENT",
        )
        password = json.loads(candidate["SecretString"])["password"]
        with self.verification.sql.login_connect(password) as db:
            db.execute("SET TRANSACTION READ ONLY")
            if db.execute("SELECT current_user,current_database()").fetchone() != (
                self.verification.preparation.restriction.fence.role,
                context["binding"]["database_name"],
            ):
                raise ValueError("Recovery workload authentication scope changed")
        guard()
        return {
            "target": "aws-ecs-standard",
            "service": submitted["service_arn"].rsplit("/", 1)[-1],
            "service_arn": submitted["service_arn"],
            "url": url,
            "health_url": url + r.health_path,
            "public": False,
            "access_scope": "operator-restricted" if r.assign_public_ip else "private",
            "account": r.account_id,
            "region": r.region,
            "owner_attempt": r.recovery_id[:16],
            "image": plan["image"],
            "image_digest": plan["image"].split("@")[1],
            "task_definition_arn": submitted["task_definition_arn"],
            "image_identity": {
                "protocol": "ecs-image-identity-v1",
                "status": "passed",
                "service_arn": submitted["service_arn"],
                "task_definition_arn": submitted["task_definition_arn"],
                "task_arns": tasks["taskArns"],
            },
            "database": {
                "secret_arn": context["secret_arn"],
                "secret_version_id": r.recovery_id,
                "binding": context["binding"],
            },
            "verification": {
                "http": "verified",
                "database_authentication": "verified",
                "application_data_path": "not_verified",
            },
        }

    def restrict(self, plan):
        r = self.r
        self.verification.sql.cleanup_restriction.fence.set_login(False, guard=lambda: None)
        name = "sky-incident-" + r.recovery_id[:16]
        response = self.clients["ecs"].describe_services(
            cluster=r.cluster_arn, services=[name], include=["TAGS"]
        )
        stopped = False
        if response.get("services"):
            service = response["services"][0]
            if {t["key"]: t["value"] for t in service.get("tags", [])}.get(
                "sky-recovery-id"
            ) != r.recovery_id:
                raise ValueError("Unknown recovery service; do not stop unrelated work")
            self.clients["ecs"].update_service(
                cluster=r.cluster_arn, service=service["serviceArn"], desiredCount=0
            )
        # Absence or an accepted update does not settle a delayed CreateService.
        return {
            "login_enabled": False,
            "candidate_stopped_verified": stopped,
            "provider_outcome_settled": False,
            "automatic_retry_allowed": False,
        }


def normalized_container(value):
    """Normalize only observed harmless ECS defaults, never execution capabilities."""
    result = deepcopy(value)
    if type(result.get("cpu")) is int and result["cpu"] == 0:
        result.pop("cpu")
    for name in ("mountPoints", "volumesFrom", "systemControls"):
        if result.get(name) == []:
            result.pop(name, None)
    capabilities = result.get("linuxParameters", {}).get("capabilities", {})
    if capabilities.get("add") == []:
        capabilities.pop("add")
    for name in ("environment", "secrets"):
        if name in result:
            items = result[name]
            if (
                not isinstance(items, list)
                or any(not isinstance(item, dict) or not isinstance(item.get("name"), str) for item in items)
                or len({item["name"] for item in items}) != len(items)
            ):
                raise ValueError("Unique approved container environment and secret names required")
            result[name] = sorted(items, key=lambda item: item["name"])
    return result


def old_policy_within_profile(value, allowed):
    if (
        not isinstance(value, dict)
        or set(value) != {"Version", "Statement"}
        or value["Version"] != "2012-10-17"
        or not isinstance(value["Statement"], list)
        or not len(value["Statement"]) <= 4
    ):
        return False
    return all(statement in allowed["Statement"] for statement in value["Statement"])
