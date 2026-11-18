"""One immutable, non-activated AWS-to-VM environment provider rehearsal."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from adapters.aws.registered_rds_inventory import RegisteredRdsInventory
from adapters.database.environment_execution_resources import RegisteredRuntimeExecutionResourceCheck
from adapters.database.environment_execution_runtime import (
    RegisteredEnvironmentRuntimeSecret,
    RegisteredEnvironmentTransferRuntime,
    RegisteredEnvironmentTransferRuntimeRegistration,
)
from adapters.database.environment_runtime_composer import (
    RegisteredAwsVmEnvironmentRuntimeComposer,
    RegisteredEnvironmentRuntimeComposition,
)
from adapters.database.environment_transfer import RegisteredTransferEndpoint
from adapters.database.migration_inventory import PostgresInventoryRegistration
from adapters.onprem.database_inventory import VmDatabaseInventoryRegistration
from adapters.onprem.environment_router import RegisteredEnvironmentRouter
from adapters.runtime.environment_secrets import (
    AwsAndPrivateEnvironmentSecretResolver,
    RegisteredAwsEnvironmentSecret,
    RegisteredPrivateRouterTransportSecret,
)
from adapters.runtime.pinned_ca import pinned_ca_bundle
from application.environment_admission import RegisteredEnvironmentExecution
from application.environment_execution_composition import RegisteredEnvironmentExecutionComposition
from application.environment_execution_effect import (
    RegisteredEnvironmentTransferEffect,
    RegisteredEnvironmentTransferResources,
)
from application.environment_gate_review import LATEST_GATE, RegisteredPreservationGatePolicy
from application.environment_jobs import RegisteredEnvironmentJob
from domain.access import ResourceOwner
from domain.database_migration import DatabaseLocation, DatabasePlacement, MigrationSafetyPolicy
from domain.database_transfer import RegisteredDatabaseTransfer
from domain.environment_transition import (
    BASELINE_CAPABILITIES,
    PreservationRequirement,
    TransitionScope,
)

PROVIDER = "sky-aws-vm-rehearsal"
REGISTRATION_ID = "aws-vm-rehearsal"
ACCOUNT = "111111111111"
REGION = "ap-northeast-2"
KEY_SHA256 = "05335ba28b27ac081a2b570a6961e3d5b5ad37542e56d35c2191d3957024c2d0"
KNOWN_HOSTS_SHA256 = "2dc37ee6bf94730b9417237b005c8bb0fff1065a533b49c8c77f9357c5cc6d8e"
RUNTIME_VERIFIER_REF = "RVR-" + "6" * 64
ENTRYPOINT_PROBE_REF = "EPR-" + "7" * 64


class _FailClosedRuntimeVerifier:
    reference = RUNTIME_VERIFIER_REF

    def __call__(self, _binding):
        raise RuntimeError("Rehearsal runtime evidence is not activated")


class _FailClosedEntrypointProbe:
    reference = ENTRYPOINT_PROBE_REF

    def __call__(self):
        raise RuntimeError("Rehearsal entrypoint evidence is not activated")


class _UnavailableSts:
    meta = SimpleNamespace(
        region_name=REGION,
        endpoint_url=f"https://sts.{REGION}.amazonaws.com",
    )

    def get_caller_identity(self):
        raise RuntimeError("Reference-only AWS client")


class _UnavailableSecrets:
    meta = SimpleNamespace(
        region_name=REGION,
        endpoint_url=f"https://secretsmanager.{REGION}.amazonaws.com",
    )

    def describe_secret(self, **_kwargs):
        raise RuntimeError("Reference-only AWS client")

    def get_secret_value(self, **_kwargs):
        raise RuntimeError("Reference-only AWS client")


class _UnavailableRds:
    meta = SimpleNamespace(region_name=REGION)

    def describe_db_instances(self, **_kwargs):
        raise RuntimeError("Reference-only AWS client")


def _execution():
    source = DatabasePlacement(
        "sky-rehearsal",
        "rehearsal-app",
        "existing_workload",
        DatabaseLocation("aws", "rds_postgresql", ACCOUNT, REGION),
        "rehearsal-source-rds",
        "rehearsal_source",
        "rehearsal-source-owner",
        17,
    )
    target = DatabasePlacement(
        "sky-rehearsal",
        "rehearsal-app",
        "existing_workload",
        DatabaseLocation("onprem", "vm_postgresql", "rehearsal-vm", "isolated-lab"),
        "rehearsal-target-db",
        "rehearsal_target",
        "rehearsal-target-owner",
        17,
    )
    transfer = RegisteredDatabaseTransfer(
        "rehearsal-route",
        source,
        target,
        "a" * 64,
        MigrationSafetyPolicy(120, 600, 86400),
    )
    scope = TransitionScope(
        source.organization_id,
        source.application_id,
        "rehearsal-aws",
        "rehearsal-vm",
        transfer.source_revision,
        "b" * 64,
        "c" * 64,
    )
    capabilities = (
        *BASELINE_CAPABILITIES,
        *(value for value in LATEST_GATE if value not in BASELINE_CAPABILITIES),
    )
    requirements = tuple(
        PreservationRequirement(value, "criterion-" + value, "d" * 64) for value in capabilities
    )
    policy = RegisteredPreservationGatePolicy(
        "rehearsal-write-pause-policy",
        scope,
        requirements,
        tuple((value, LATEST_GATE[value]) for value in capabilities),
    )
    job = RegisteredEnvironmentJob(
        REGISTRATION_ID,
        ResourceOwner(source.organization_id, "operator"),
        transfer,
        datetime(2027, 11, 19, tzinfo=UTC),
        "https://gateway.rehearsal.invalid:8443/",
        "e" * 64,
    )
    return RegisteredEnvironmentExecution(job, policy, transfer.registration_ref)


def _router_transport():
    version = hashlib.sha256(
        json.dumps(
            {
                "profile": "private-router-transport-v1",
                "private_key_sha256": KEY_SHA256,
                "known_hosts_sha256": KNOWN_HOSTS_SHA256,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    key = Path(
        os.environ.get(
            "SKY_REHEARSAL_ROUTER_PRIVATE_KEY",
            "/run/secrets/sky-rehearsal/router-private-key",
        )
    )
    hosts = Path(
        os.environ.get(
            "SKY_REHEARSAL_ROUTER_KNOWN_HOSTS",
            "/run/secrets/sky-rehearsal/router-known-hosts",
        )
    )
    return RegisteredPrivateRouterTransportSecret(
        "rehearsal-router-transport",
        "files-" + version,
        key,
        hosts,
        KEY_SHA256,
        KNOWN_HOSTS_SHA256,
    )


def _aws_secrets():
    tags = (("sky-application-id", "rehearsal-app"), ("sky-managed", "true"))
    values = []
    for index, purpose in enumerate(
        (
            "entrypoint_probe",
            "source_control",
            "source_database",
            "target_control",
            "target_database",
        ),
        start=1,
    ):
        values.append(
            RegisteredAwsEnvironmentSecret(
                purpose,
                "rehearsal-" + purpose.replace("_", "-"),
                format(index, "032x"),
                f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:sky/rehearsal/{purpose}-abc123",
                tags,
            )
        )
    return tuple(values)


def _registrations(execution):
    transfer = execution.job.transfer
    ca = Path(__file__).with_name("ca.pem").resolve()
    _ca_content, ca_sha256 = pinned_ca_bundle(ca)
    source_role = "sky_transfer_" + "1" * 16
    target_role = "sky_transfer_" + "2" * 16
    source_endpoint = RegisteredTransferEndpoint(
        PostgresInventoryRegistration(
            transfer.source,
            "source-db.rehearsal.invalid",
            5432,
            source_role,
            str(ca),
            ca_sha256,
        ),
        35432,
        "127.0.0.1",
    )
    target_endpoint = RegisteredTransferEndpoint(
        PostgresInventoryRegistration(
            transfer.target,
            "target-db.rehearsal.invalid",
            5432,
            target_role,
            str(ca),
            ca_sha256,
        ),
        45432,
        "127.0.0.1",
    )
    source_rds = RegisteredRdsInventory(
        transfer.source,
        "db-rehearsalimmutable",
        source_endpoint.inventory.hostname,
        source_endpoint.inventory.port,
        "vpc-12345678",
        ("sg-12345678",),
        (("sky-application-id", "rehearsal-app"), ("sky-managed", "true")),
    )
    target_vm = VmDatabaseInventoryRegistration(
        transfer.target,
        "rehearsal-daemon-1234",
        "3" * 64,
        "sha256:" + "4" * 64,
        "rehearsal-database-volume",
        target_endpoint.inventory.hostname,
        target_endpoint.inventory.port,
    )
    router = RegisteredEnvironmentRouter(
        transfer,
        target_vm.daemon_id,
        "5" * 64,
        "sha256:" + "8" * 64,
        "10.0.0.10",
        8443,
        "source-app.rehearsal.invalid",
        "172.16.0.10",
        8443,
        "target-app.rehearsal.invalid",
        "rehearsal-network",
        "rehearsal-router-config",
    )
    composition = RegisteredEnvironmentRuntimeComposition(
        execution.revision,
        source_endpoint,
        target_endpoint,
        source_rds,
        target_vm,
        router,
        "127.0.0.1",
        "operator",
        2222,
        source_role,
        target_role,
        "sky-transfer-v1:" + "9" * 64,
        "sky-transfer-v1:" + "a" * 64,
        "https://source-app.rehearsal.invalid:38443/control",
        "127.0.0.1",
        "rehearsal-source-controller",
        "https://target-app.rehearsal.invalid:48443/control",
        "127.0.0.1",
        "rehearsal-target-controller",
        str(ca),
        ca_sha256,
        RUNTIME_VERIFIER_REF,
        ENTRYPOINT_PROBE_REF,
    )
    return composition


def _compose(selected, *, sts, secretsmanager, rds):
    if selected != (REGISTRATION_ID,):
        raise ValueError("Exact rehearsal execution selection required")
    execution = _execution()
    aws_secrets = _aws_secrets()
    router_transport = _router_transport()
    resolver = AwsAndPrivateEnvironmentSecretResolver(
        execution_revision=execution.revision,
        account_id=ACCOUNT,
        region=REGION,
        aws_secrets=aws_secrets,
        router_transport=router_transport,
        sts=sts,
        secretsmanager=secretsmanager,
    )
    composition = _registrations(execution)
    composer = RegisteredAwsVmEnvironmentRuntimeComposer(
        execution,
        composition,
        sts=sts,
        rds=rds,
        runtime_verifier=_FailClosedRuntimeVerifier(),
        entrypoint_probe=_FailClosedEntrypointProbe(),
    )
    secrets = {
        "router_transport": router_transport,
        **{value.purpose: value for value in aws_secrets},
    }
    purposes = (
        "router_transport",
        "entrypoint_probe",
        "source_control",
        "source_database",
        "target_control",
        "target_database",
    )
    runtime_registration = RegisteredEnvironmentTransferRuntimeRegistration(
        execution.revision,
        resolver.reference,
        composer.reference,
        tuple(
            RegisteredEnvironmentRuntimeSecret(
                purpose,
                secrets[purpose].secret_ref,
                secrets[purpose].version_ref,
            )
            for purpose in purposes
        ),
    )
    runtime = RegisteredEnvironmentTransferRuntime(
        execution,
        runtime_registration,
        resolver,
        composer,
    )
    runtime_check = RegisteredRuntimeExecutionResourceCheck(execution, runtime.reference, runtime)
    resources = RegisteredEnvironmentTransferResources(execution, (runtime_check.check(),))
    effect = RegisteredEnvironmentTransferEffect(execution, runtime.reference, runtime)
    return (
        RegisteredEnvironmentExecutionComposition(
            execution,
            resources.reference,
            resources,
            effect.reference,
            effect,
        ),
    )


def provider_pins():
    """Return the exact public descriptor pins without creating AWS clients."""
    (composition,) = _compose(
        (REGISTRATION_ID,),
        sts=_UnavailableSts(),
        secretsmanager=_UnavailableSecrets(),
        rds=_UnavailableRds(),
    )
    return {
        "registration_id": REGISTRATION_ID,
        "execution_revision": composition.execution.revision,
        "application_id": composition.execution.job.transfer.source.application_id,
        "resource_verifier_ref": composition.resource_verifier_ref,
        "effect_ref": composition.effect_ref,
    }


def provide(selected):
    """Compose only the descriptor-approved rehearsal using ambient AWS identity."""
    import boto3

    session = boto3.Session(region_name=REGION)
    return _compose(
        selected,
        sts=session.client("sts", region_name=REGION),
        secretsmanager=session.client("secretsmanager", region_name=REGION),
        rds=session.client("rds", region_name=REGION),
    )
