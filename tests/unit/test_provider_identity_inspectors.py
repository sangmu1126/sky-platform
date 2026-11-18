"""AWS and HTTPS inspectors use only pinned read-only identity operations."""

import hashlib
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from adapters.aws.provider_identity import (
    AwsProviderIdentityInspector,
    RegisteredAwsProviderIdentityTarget,
    aws_provider_identity_authority_ref,
    aws_resource_identity_sha256,
)
from adapters.runtime.https_provider_identity import (
    PinnedHttpsProviderIdentityInspector,
    RegisteredHttpsProviderIdentityTarget,
    https_provider_identity_authority_ref,
    https_resource_identity_sha256,
)
from adapters.runtime.provider_identity import (
    ProviderIdentityEvidenceReader,
    ProviderIdentityInspectorRouter,
    RegisteredProviderIdentityInventory,
    RegisteredProviderResourceIdentity,
)
from tests.unit.test_environment_transition import NOW
from tests.unit.test_workload_inventory import registration

ACCOUNT = "111111111111"
REGION = "ap-northeast-2"


def aws_case():
    authority = aws_provider_identity_authority_ref(
        ACCOUNT, REGION, "runtime-provider-role", "SkyRuntimeInventory"
    )
    owner = "a" * 64
    queue_arn = f"arn:aws:sqs:{REGION}:{ACCOUNT}:jobs.fifo"
    resources = (
        RegisteredProviderResourceIdentity(
            "jobs-queue",
            "queue",
            "aws-queue",
            "aws",
            "sqs-queue",
            "jobs-queue-target",
            aws_resource_identity_sha256(
                resource_kind="sqs-queue",
                account_id=ACCOUNT,
                region=REGION,
                identity=queue_arn,
            ),
            authority,
        ),
        RegisteredProviderResourceIdentity(
            "uploads",
            "object_store",
            "aws-objects",
            "aws",
            "s3-bucket",
            "uploads-bucket-target",
            aws_resource_identity_sha256(
                resource_kind="s3-bucket",
                account_id=ACCOUNT,
                region=REGION,
                identity="sky-runtime-uploads:" + owner,
            ),
            authority,
        ),
    )
    targets = (
        RegisteredAwsProviderIdentityTarget(
            "jobs-queue-target",
            "sqs-queue",
            queue_url=f"https://sqs.{REGION}.amazonaws.com/{ACCOUNT}/jobs.fifo",
        ),
        RegisteredAwsProviderIdentityTarget(
            "uploads-bucket-target",
            "s3-bucket",
            bucket_name="sky-runtime-uploads",
        ),
    )
    sts = Mock(
        get_caller_identity=Mock(
            return_value={
                "Account": ACCOUNT,
                "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/SkyRuntimeInventory/test-session",
            }
        )
    )
    s3 = Mock(
        get_bucket_acl=Mock(return_value={"Owner": {"ID": owner}}),
        get_bucket_location=Mock(return_value={"LocationConstraint": REGION}),
    )
    sqs = Mock(get_queue_attributes=Mock(return_value={"Attributes": {"QueueArn": queue_arn}}))
    inspector = AwsProviderIdentityInspector(
        account_id=ACCOUNT,
        region=REGION,
        authority_ref=authority,
        credential_source_ref="runtime-provider-role",
        principal_role_ref="SkyRuntimeInventory",
        targets=targets,
        sts=sts,
        s3=s3,
        sqs=sqs,
        clock=lambda: NOW,
    )
    return inspector, resources, sts, s3, sqs


def test_aws_inspector_reads_exact_s3_owner_region_and_sqs_arn():
    inspector, resources, sts, s3, sqs = aws_case()
    queue = inspector.inspect(resources[0])
    bucket = inspector.inspect(resources[1])
    assert queue.identity_sha256 == resources[0].identity_sha256
    assert bucket.identity_sha256 == resources[1].identity_sha256
    assert sts.get_caller_identity.call_count == 2
    s3.get_bucket_acl.assert_called_once_with(Bucket="sky-runtime-uploads", ExpectedBucketOwner=ACCOUNT)
    s3.get_bucket_location.assert_called_once_with(Bucket="sky-runtime-uploads", ExpectedBucketOwner=ACCOUNT)
    sqs.get_queue_attributes.assert_called_once_with(
        QueueUrl=f"https://sqs.{REGION}.amazonaws.com/{ACCOUNT}/jobs.fifo",
        AttributeNames=["QueueArn"],
    )


@pytest.mark.parametrize("change", ["account", "region", "queue_arn"])
def test_aws_identity_drift_is_sanitized(change):
    inspector, resources, sts, s3, sqs = aws_case()
    resource = resources[1]
    if change == "account":
        sts.get_caller_identity.return_value = {
            "Account": "222222222222",
            "Arn": "arn:aws:sts::222222222222:assumed-role/SkyRuntimeInventory/foreign",
        }
    elif change == "region":
        s3.get_bucket_location.return_value = {"LocationConstraint": "us-east-1"}
    else:
        resource = resources[0]
        sqs.get_queue_attributes.return_value = {
            "Attributes": {"QueueArn": f"arn:aws:sqs:{REGION}:222222222222:jobs.fifo"}
        }
    with pytest.raises(OSError, match="Registered AWS provider identity unavailable") as error:
        inspector.inspect(resource)
    assert "222222222222" not in str(error.value)


def certificate(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.partner.example")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    ca = tmp_path / "provider-ca.pem"
    ca.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    ca.chmod(0o644)
    spki = hashlib.sha256(
        key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()
    return ca, certificate.public_bytes(serialization.Encoding.DER), spki


def https_case(tmp_path):
    ca, leaf, spki = certificate(tmp_path)
    authority = https_provider_identity_authority_ref(ca, "partner-api-trust")
    target = RegisteredHttpsProviderIdentityTarget(
        "partner-api-target",
        "api.partner.example",
        443,
        spki,
    )
    resource = RegisteredProviderResourceIdentity(
        "partner-api",
        "external_api",
        "partner-service",
        "https",
        "https-service",
        target.resource_ref,
        https_resource_identity_sha256(
            host=target.host,
            port=target.port,
            spki_sha256=spki,
        ),
        authority,
    )
    connector = Mock(return_value=leaf)
    inspector = PinnedHttpsProviderIdentityInspector(
        authority_ref=authority,
        trust_profile_ref="partner-api-trust",
        ca_bundle=ca,
        targets=(target,),
        clock=lambda: NOW,
        connector=connector,
    )
    return inspector, resource, connector, ca


def test_https_inspector_binds_ca_sni_port_and_leaf_spki(tmp_path):
    inspector, resource, connector, _ca = https_case(tmp_path)
    observed = inspector.inspect(resource)
    assert observed.identity_sha256 == resource.identity_sha256
    assert observed.authority_ref == inspector.authority_ref
    arguments = connector.call_args.args
    assert arguments[1:] == ("api.partner.example", 443, 5)
    assert arguments[0].check_hostname and arguments[0].verify_mode.name == "CERT_REQUIRED"


def test_https_ca_or_leaf_key_drift_is_rejected_before_evidence(tmp_path):
    inspector, resource, connector, ca = https_case(tmp_path)
    ca.write_bytes(ca.read_bytes() + b"\n")
    with pytest.raises(OSError, match="Registered HTTPS provider identity unavailable"):
        inspector.inspect(resource)
    connector.assert_not_called()

    inspector, resource, connector, _ca = https_case(tmp_path / "second")
    inspector.targets[resource.resource_ref] = RegisteredHttpsProviderIdentityTarget(
        resource.resource_ref,
        "api.partner.example",
        443,
        "f" * 64,
    )
    with pytest.raises(OSError, match="Registered HTTPS provider identity unavailable"):
        inspector.inspect(resource)


def test_mixed_aws_and_https_resources_form_one_verified_provider_report(tmp_path):
    aws, aws_resources, _sts, _s3, _sqs = aws_case()
    https, https_resource, _connector, _ca = https_case(tmp_path)
    resources = tuple(sorted((https_resource, aws_resources[1]), key=lambda value: value.logical_ref))
    registered = RegisteredProviderIdentityInventory(
        registration(),
        "source",
        "multi-provider-collector",
        resources,
    )
    reports = {}

    class Publisher:
        def publish(self, report):
            reports[report["report_id"]] = report
            return report["report_id"]

    reader = ProviderIdentityEvidenceReader(
        registered,
        ProviderIdentityInspectorRouter((("aws", aws), ("https", https))),
        Publisher(),
        clock=lambda: NOW,
    )
    evidence = reader.collect(registered.inventory, "source")
    assert reports[evidence.report_id]["status"] == "verified"
    assert all(value["identity_verified"] for value in reports[evidence.report_id]["resources"])
