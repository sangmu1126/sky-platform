"""VM controls are fixed by operator registration, independently of user source."""

from datetime import UTC, datetime
from unittest.mock import Mock

import pytest

from adapters.aws.build_sandbox import AwsBuildSandbox
from adapters.build.sandbox_profile import SandboxProfile

JOB = "00000000-0000-4000-8000-000000000001"


def profile():
    return SandboxProfile(
        name="sky-test",
        account_id="123456789012",
        region="ap-northeast-2",
        vpc_id="vpc-12345678",
        subnet_id="subnet-12345678",
        security_group_id="sg-12345678",
        operator_cidr="8.8.8.8/32",
        scheduler_role_arn="arn:aws:iam::123456789012:role/sky-deadline",
        scheduler_group="sky-test",
        reaper_arn="arn:aws:lambda:ap-northeast-2:123456789012:function:sky-reaper",
        ami_id="ami-12345678",
        ami_owner="591542846629",
    )


def setup_sandbox(monkeypatch):
    p, ec2, scheduler, sts, session = profile(), Mock(), Mock(), Mock(), Mock()
    session.client.side_effect = lambda name, **_: {"ec2": ec2, "scheduler": scheduler, "sts": sts}[name]
    monkeypatch.setattr(SandboxProfile, "verify_network", lambda *_: None)
    sts.get_caller_identity.return_value = {"Account": p.account_id}
    instance = {
        "InstanceId": "i-12345678",
        "VpcId": p.vpc_id,
        "SecurityGroups": [{"GroupId": p.security_group_id}],
        "MetadataOptions": {"HttpEndpoint": "disabled", "State": "applied"},
        "State": {"Name": "running"},
        "Tags": [
            {"Key": "app", "Value": "sky"},
            {"Key": "sky:SandboxProfile", "Value": p.name},
            {"Key": "sky:JobId", "Value": JOB},
        ],
    }
    ec2.run_instances.return_value = {"Instances": [instance]}
    ec2.describe_instances.return_value = {
        "Reservations": [{"OwnerId": p.account_id, "Instances": [instance]}]
    }
    events = []
    scheduler.create_schedule.side_effect = lambda **_: events.append("deadline")
    ec2.import_key_pair.side_effect = lambda **_: events.append("key")
    original = ec2.run_instances.return_value
    ec2.run_instances.side_effect = lambda **_: events.append("vm") or original
    sandbox = AwsBuildSandbox(p, session, Mock(), now=lambda: datetime(2026, 10, 30, tzinfo=UTC))
    return sandbox, ec2, scheduler, instance, events


def test_deadline_precedes_vm_and_guest_has_no_credentials(monkeypatch):
    sandbox, ec2, scheduler, _, events = setup_sandbox(monkeypatch)
    receipt = sandbox.launch(JOB, "ssh-ed25519 AAAAtest")
    assert events == ["deadline", "key", "vm"]
    args = ec2.run_instances.call_args.kwargs
    assert "IamInstanceProfile" not in args
    assert args["MetadataOptions"]["HttpEndpoint"] == "enabled"
    assert receipt["source_transfer_allowed"] is False
    assert args["MinCount"] == args["MaxCount"] == 1
    assert args["CreditSpecification"] == {"CpuCredits": "standard"}
    disk = args["BlockDeviceMappings"][0]["Ebs"]
    assert disk["Encrypted"] and disk["DeleteOnTermination"] and disk["VolumeSize"] == 30
    assert scheduler.create_schedule.call_args.kwargs["Target"]["Input"] == '{"job_id":"' + JOB + '"}'
    assert receipt["credentials_in_guest"] is False


def test_deadline_failure_never_starts_billable_vm(monkeypatch):
    sandbox, ec2, scheduler, _, _ = setup_sandbox(monkeypatch)
    scheduler.create_schedule.side_effect = OSError("uncertain deadline write")
    with pytest.raises(OSError):
        sandbox.launch(JOB, "ssh-ed25519 AAAAtest")
    ec2.run_instances.assert_not_called()
    ec2.import_key_pair.assert_not_called()


@pytest.mark.parametrize("change", ["profile", "group", "app", "job"])
def test_foreign_or_credential_enabled_guest_cannot_be_finalized(monkeypatch, change):
    sandbox, ec2, _, instance, _ = setup_sandbox(monkeypatch)
    receipt = sandbox.launch(JOB, "ssh-ed25519 AAAAtest")
    if change == "profile":
        instance["IamInstanceProfile"] = {"Arn": "foreign"}
    elif change == "metadata":
        instance["MetadataOptions"]["HttpEndpoint"] = "enabled"
    elif change == "group":
        instance["SecurityGroups"].append({"GroupId": "sg-foreign"})
    else:
        instance["Tags"] = [
            t for t in instance["Tags"] if t["Key"] != ("app" if change == "app" else "sky:JobId")
        ]
    with pytest.raises(ValueError):
        sandbox.terminate(receipt)
    ec2.terminate_instances.assert_not_called()
    ec2.delete_key_pair.assert_not_called()


def test_key_is_kept_until_termination_is_observed(monkeypatch):
    sandbox, ec2, _, instance, _ = setup_sandbox(monkeypatch)
    receipt = sandbox.launch(JOB, "ssh-ed25519 AAAAtest")
    sandbox.terminate(receipt)
    with pytest.raises(ValueError, match="not terminated"):
        sandbox.finalize(receipt)
    ec2.delete_key_pair.assert_not_called()
    instance["State"]["Name"] = "terminated"
    assert sandbox.finalize(receipt)["termination_confirmed"]
    ec2.delete_key_pair.assert_called_once()


def test_authorization_revocation_prevents_all_further_cloud_calls(monkeypatch):
    sandbox, ec2, scheduler, _, _ = setup_sandbox(monkeypatch)
    sandbox.guard.side_effect = ValueError("revoked")
    with pytest.raises(ValueError, match="revoked"):
        sandbox.launch(JOB, "ssh-ed25519 AAAAtest")
    ec2.run_instances.assert_not_called()
    scheduler.create_schedule.assert_not_called()


def test_terminated_guest_keeps_job_ownership_but_loses_network_fields(monkeypatch):
    sandbox, ec2, _, instance, _ = setup_sandbox(monkeypatch)
    receipt = sandbox.launch(JOB, "ssh-ed25519 AAAAtest")
    instance["State"]["Name"] = "terminated"
    instance.pop("VpcId")
    instance["SecurityGroups"] = []
    receipt["key_name"] = "do-not-delete-other-job"
    assert sandbox.finalize(receipt)["termination_confirmed"]
    ec2.delete_key_pair.assert_called_once_with(KeyName="sky-test-" + JOB)
