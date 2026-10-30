"""Deploy an approved, verified image without Docker or infrastructure mutations."""
import re
import urllib.request

from adapters.github.remote_build import NoRedirect
from ports.remote_builds import digest, validate_request


class BuiltImageDeployment:
    def __init__(self, settings, *, ecs=None, stacks=None, identity=None, probe=None, database_profile=None, deployment_id=None):
        self.settings = settings
        if deployment_id is not None:
            from ports.remote_builds import identity as validate_identity
            validate_identity(deployment_id)
        self.deployment_id = deployment_id
        if database_profile is not None:
            from adapters.aws.postgres_build_profile import SharedPostgresBuildProfile
            if not isinstance(database_profile, SharedPostgresBuildProfile):
                raise TypeError("Registered shared PostgreSQL build profile required")
        self.database_profile = database_profile
        if any(client is None for client in (ecs, stacks, identity)):
            import boto3
            from botocore.config import Config
            config = Config(connect_timeout=5, read_timeout=20, retries={"total_max_attempts": 1})
            ecs = ecs or boto3.client("ecs", region_name=settings.region, config=config)
            stacks = stacks or boto3.client("cloudformation", region_name=settings.region, config=config)
            identity = identity or boto3.client("sts", region_name=settings.region, config=config)
        self.ecs, self.stacks, self.identity = ecs, stacks, identity
        self.probe = probe or self.http_probe

    @staticmethod
    def http_probe(url):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(url, timeout=5) as response:
            if response.status != 200:
                raise OSError("Deployment HTTP verification unavailable")

    def prepare(self, request, result):
        from botocore.exceptions import BotoCoreError, ClientError
        artifact, plan = validate_request(request)
        if (request["account_id"], request["region"]) != (self.settings.account_id, self.settings.region):
            raise ValueError("Deployment account scope changed")
        if ((plan.get("required_env") and self.database_profile is None) or plan.get("replicas") != 1
                or type(plan.get("port")) is not int or not 1024 <= plan["port"] <= 65535
                or not isinstance(plan.get("health_path"), str)
                or len(plan["health_path"]) > 200
                or not re.fullmatch(r"/[A-Za-z0-9/_.-]*", plan["health_path"])
                or ".." in plan["health_path"] or "//" in plan["health_path"]):
            raise ValueError("Deployment requires a bounded, environment-free HTTP plan")
        from ports.remote_builds import validate_result
        if type(result.get("run_id")) is not int or result["run_id"] < 1:
            raise ValueError("Verified workflow run identity required")
        validate_result(result, request, result["run_id"])
        profile = plan.get("infrastructure_profile", {})
        if self.database_profile is None and (
            plan.get("database_profile") is not None or not isinstance(profile, dict)
            or profile.get("requirements") or profile.get("database_engines")
        ):
            raise ValueError("Stateless deployment cannot discard infrastructure requirements")
        database = self.database_profile.prepare(request, result, plan) if self.database_profile else None
        try:
            if self.identity.get_caller_identity()["Account"] != self.settings.account_id:
                raise ValueError("Deployment caller account changed")
            stacks = self.stacks.describe_stacks(StackName="sky-core")["Stacks"]
        except (BotoCoreError, ClientError):
            raise OSError("Deployment infrastructure inspection unavailable") from None
        if (len(stacks) != 1 or stacks[0].get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
                or {x["Key"]: x["Value"] for x in stacks[0].get("Tags", [])}.get("sky-managed") != "true"):
            raise ValueError("Managed core stack is not ready")
        outputs = {x["OutputKey"]: x["OutputValue"] for x in stacks[0].get("Outputs", [])}
        if outputs.get("RepositoryUri") != result["image"].split("@")[0]:
            raise ValueError("Managed repository changed")
        roles = [outputs.get(k, "") for k in ("ExecutionRoleArn", "InfrastructureRoleArn")]
        for role, logical in zip(roles, ("ExecutionRole", "InfrastructureRole")):
            if not re.fullmatch(r"arn:aws:iam::" + self.settings.account_id + r":role/sky-core-" + logical + r"-[A-Za-z0-9]+", role):
                raise ValueError("Managed core role changed")
        deployment_id = self.deployment_id or request["build_id"]
        service = "sky-b-" + deployment_id.replace("-", "")
        arn = f"arn:aws:ecs:{self.settings.region}:{self.settings.account_id}:service/default/{service}"
        tags = {"sky-managed": "true", "sky-operation": deployment_id,
                "sky-attempt": deployment_id.replace("-", "")[:16],
                "sky-workspace": request["workspace"], "sky-application": artifact.application_id,
                "sky-organization": artifact.organization_id}
        if self.deployment_id is not None:
            tags["sky-build"] = request["build_id"]
        payload = {"serviceName": service, "cluster": "default", "executionRoleArn": roles[0],
                   "infrastructureRoleArn": roles[1], "cpuArchitecture": "X86_64",
                   "healthCheckPath": plan["health_path"],
                   "primaryContainer": {"image": result["image"], "containerPort": plan["port"],
                                        "environment": [{"name": "PORT", "value": str(plan["port"])}]},
                   "scalingTarget": {"minTaskCount": 1, "maxTaskCount": 1},
                   "tags": [{"key": k, "value": v} for k, v in tags.items()]}
        if database is not None:
            selected = self.database_profile.payload(database)
            payload["executionRoleArn"] = selected["executionRoleArn"]
            payload["networkConfiguration"] = selected["networkConfiguration"]
            payload["primaryContainer"]["environment"].extend(selected["environment"])
            payload["primaryContainer"]["secrets"] = selected["secrets"]
            payload["primaryContainer"]["awsLogsConfiguration"] = selected["awsLogsConfiguration"]
        # No create retries: Express has no clientToken. An uncertain request is parked by the caller.
        try:
            self.ecs.describe_express_gateway_service(serviceArn=arn, include=["TAGS"])
        except ClientError as error:
            if error.response["Error"]["Code"] != "ResourceNotFoundException":
                raise OSError("Deployment identity inspection unavailable") from None
        except BotoCoreError:
            raise OSError("Deployment identity inspection unavailable") from None
        else:
            raise ValueError("Deployment identity already exists; reconciliation required")
        intent = {"kind": "ecs_deployment", "service_arn": arn, "payload": payload,
                  "request_digest": digest(request), "image": result["image"]}
        if database is not None:
            intent["database_registration"] = database
        return intent

    def create(self, intent):
        from botocore.exceptions import BotoCoreError, ClientError
        try:
            service = self.ecs.create_express_gateway_service(**intent["payload"])["service"]
        except (BotoCoreError, ClientError):
            raise OSError("Deployment submission requires reconciliation") from None
        if service.get("serviceArn") != intent["service_arn"]:
            raise ValueError("Deployment submission identity changed")

    def observe(self, intent):
        from botocore.exceptions import BotoCoreError, ClientError
        try:
            service = self.ecs.describe_express_gateway_service(serviceArn=intent["service_arn"], include=["TAGS"])["service"]
            tags = {x["key"]: x["value"] for x in service.get("tags", [])}
            expected = {x["key"]: x["value"] for x in intent["payload"]["tags"]}
            if service.get("serviceArn") != intent["service_arn"] or any(tags.get(k) != v for k, v in expected.items()):
                raise ValueError("Deployment ownership changed")
            status = service.get("status", {}).get("statusCode")
            if status in {"FAILED", "INACTIVE"}:
                raise ValueError("Deployment is not healthy; reconciliation required")
            if status != "ACTIVE":
                return None
            deployment = service.get("currentDeployment")
            if deployment:
                prefix = f"arn:aws:ecs:{self.settings.region}:{self.settings.account_id}:service-deployment/default/{intent['payload']['serviceName']}/"
                if not isinstance(deployment, str) or not re.fullmatch(
                    re.escape(prefix) + r"[A-Za-z0-9_-]{1,128}", deployment
                ):
                    raise ValueError("Current deployment belongs to another service")
                observed = self.ecs.describe_service_deployments(serviceDeploymentArns=[deployment])
                deployments = observed.get("serviceDeployments", [])
                if (
                    observed.get("failures")
                    or len(deployments) != 1
                    or deployments[0].get("serviceDeploymentArn") != deployment
                    or deployments[0].get("serviceArn") != intent["service_arn"]
                ):
                    raise ValueError("Exact current deployment observation required")
                if deployments[0].get("status") in {"PENDING", "IN_PROGRESS"}:
                    return None
                if deployments[0].get("status") != "SUCCESSFUL":
                    raise ValueError("Current deployment did not complete successfully")
            configs = service.get("activeConfigurations", [])
            if len(configs) != 1:
                return None
            c, payload = configs[0], intent["payload"]
            container = c.get("primaryContainer", {})
            def same_container_field(key, expected):
                value = container.get(key, [] if key in {"environment", "secrets"} else None)
                if key in {"environment", "secrets"}:
                    if not isinstance(value, list) or len({x.get("name") for x in value}) != len(value):
                        return False
                    return sorted(value, key=lambda x: x["name"]) == sorted(expected, key=lambda x: x["name"])
                return value == expected
            if (any(not same_container_field(k, v) for k, v in payload["primaryContainer"].items())
                    or not same_container_field("secrets", payload["primaryContainer"].get("secrets", []))
                    or container.get("command") or container.get("repositoryCredentials")
                    or any(c.get(k) != payload[k] for k in ("executionRoleArn", "healthCheckPath"))
                    or any(c.get("scalingTarget", {}).get(k) != v for k, v in payload["scalingTarget"].items())
                    or c.get("taskRoleArn")):
                raise ValueError("Deployment configuration differs from approval")
            if "database_registration" in intent:
                if self.database_profile is None:
                    raise ValueError("Database network or runtime registration changed")
                self.database_profile.verify_network(intent, c.get("networkConfiguration"))
            task = c.get("taskDefinitionArn", "")
            if not re.fullmatch(r"arn:aws:ecs:" + self.settings.region + ":" + self.settings.account_id + r":task-definition/[A-Za-z0-9_-]+:[0-9]+", task):
                raise ValueError("Deployment task definition changed")
            containers = self.ecs.describe_task_definition(taskDefinition=task)["taskDefinition"].get("containerDefinitions", [])
            if len(containers) != 1 or containers[0].get("name") != "Main" or containers[0].get("image") != intent["image"]:
                raise ValueError("Deployment image differs from verified build")
            paths = [p["endpoint"] for p in c.get("ingressPaths", []) if p.get("accessType") == "PUBLIC" and p.get("endpoint")]
            if len(paths) != 1:
                return None
            url = paths[0].rstrip("/")
            if not url.startswith("https://"):
                url = "https://" + url
            from urllib.parse import urlsplit
            parsed = urlsplit(url)
            hostname = parsed.hostname or ""
            label = hostname.removesuffix(f".ecs.{self.settings.region}.on.aws")
            if (parsed.scheme != "https" or label == hostname
                    or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", label)
                    or parsed.username or parsed.password or parsed.port
                    or parsed.path or parsed.query or parsed.fragment):
                raise ValueError("Deployment endpoint is outside ECS Express")
            self.probe(url + payload["healthCheckPath"])
            result = {"target": "aws-ecs-express", "service": payload["serviceName"], "service_arn": intent["service_arn"],
                    "owner_attempt": next((t["value"] for t in payload["tags"] if t["key"] == "sky-attempt"),
                                          payload["serviceName"].removeprefix("sky-b-")[:16]),
                    "url": url, "health_url": url + payload["healthCheckPath"], "public": True,
                    "image": intent["image"], "image_digest": intent["image"].split("@")[1],
                    "task_definition_arn": task, "account": self.settings.account_id, "region": self.settings.region,
                    "verification": {"http": "verified", "image": "verified"}}
            if "database_registration" in intent:
                result["database"] = self.database_profile.verify(intent)
                from adapters.aws.postgres_build_profile import verify_postgres_task
                result["image_identity"] = verify_postgres_task(self.ecs, intent, task)
                result["verification"].update(database_authentication="verified", application_data_path="not_verified")
            return result
        except (BotoCoreError, ClientError):
            raise OSError("Deployment observation unavailable") from None

    def retire(self, intent):
        """Delete only the exact recorded service after fresh ownership checks."""
        service = self.ecs.describe_express_gateway_service(
            serviceArn=intent["service_arn"], include=["TAGS"]
        )["service"]
        expected = {t["key"]: t["value"] for t in intent["payload"]["tags"]}
        actual = {t["key"]: t["value"] for t in service.get("tags", [])}
        if service.get("serviceArn") != intent["service_arn"] or any(
            actual.get(k) != v for k, v in expected.items()
        ):
            raise PermissionError("Cannot retire an unowned deployment")
        response = self.ecs.delete_express_gateway_service(serviceArn=intent["service_arn"])
        if response.get("service", {}).get("serviceArn") != intent["service_arn"]:
            raise ValueError("Retirement outcome requires reconciliation")
        return {"service_arn": intent["service_arn"], "deletion_requested": True, "deletion_complete": False}
