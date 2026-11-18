"""Installed provider and operator pins are both required for hosted execution."""

import base64
import csv
import hashlib
import io
import json
import os
from pathlib import PurePosixPath
from unittest.mock import Mock, patch

import pytest

from application.environment_execution_composition import (
    RegisteredEnvironmentEffectRouter,
    RegisteredEnvironmentExecutionComposition,
    RegisteredEnvironmentResourceRouter,
)
from interfaces.b_runtime import main
from interfaces.environment_execution_manifest import main as render_manifest
from interfaces.environment_execution_provider import main as inspect_provider
from interfaces.environment_execution_registration import (
    ENTRY_POINT_GROUP,
    EnvironmentProviderArtifact,
    attest_environment_execution_provider,
    compose_environment_executions,
    environment_execution_entry_points,
    load_environment_execution_manifest,
    render_environment_execution_manifest,
)
from tests.unit.test_environment_admission import registered


def seal_provider(root):
    for path in sorted(root.rglob("*"), key=lambda value: len(value.parts), reverse=True):
        path.chmod(0o500 if path.is_dir() else 0o400)
    root.chmod(0o500)


def composition():
    execution = registered()
    resource_ref = "EVR-" + "a" * 64
    effect_ref = "EEF-" + "b" * 64
    resources = Mock(verify=Mock(return_value={"verified": True}), reference=resource_ref)
    effect = Mock(return_value={"result_ref": "result"}, reference=effect_ref)
    return RegisteredEnvironmentExecutionComposition(
        execution,
        resource_ref,
        resources,
        effect_ref,
        effect,
    )


def manifest_file(tmp_path, selected, entry_point=None, **changes):
    artifact = (
        attest_environment_execution_provider(entry_point)
        if entry_point is not None
        else EnvironmentProviderArtifact("installed-provider", "sky-environment-provider", "1.2.3", "c" * 64)
    )
    value = {
        "schema_version": 2,
        "profile": "reviewed_environment_execution_worker_v2",
        "workspace": "test",
        **artifact.document(),
        "registrations": [
            {
                "registration_id": selected.execution.job.id,
                "execution_revision": selected.execution.revision,
                "application_id": selected.execution.job.transfer.source.application_id,
                "resource_verifier_ref": selected.resource_verifier_ref,
                "effect_ref": selected.effect_ref,
            }
        ],
    }
    value.update(changes)
    path = tmp_path / "environment-worker.json"
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return path


class Distribution:
    def __init__(self, root, source="def provide(selected): return ()\n", selected=None):
        self.root = root
        self.metadata = {"Name": "sky-environment-provider"}
        self.version = "1.2.3"
        execution = selected.execution if selected is not None else None
        registrations = [
            {
                "registration_id": execution.job.id if execution is not None else "game",
                "execution_revision": execution.revision if execution is not None else "d" * 64,
                "application_id": (
                    execution.job.transfer.source.application_id if execution is not None else "app"
                ),
                "resource_verifier_ref": (
                    selected.resource_verifier_ref if selected is not None else "EVR-" + "a" * 64
                ),
                "effect_ref": selected.effect_ref if selected is not None else "EEF-" + "b" * 64,
            }
        ]
        documents = {
            "sky_env_provider.py": source,
            "sky_environment_provider-1.2.3.dist-info/METADATA": (
                "Name: sky-environment-provider\nVersion: 1.2.3\n"
            ),
            "sky_environment_provider-1.2.3.dist-info/entry_points.txt": (
                "[sky.environment_execution.v1]\ninstalled-provider=sky_env_provider:provide\n"
            ),
            "sky_environment_provider-1.2.3.dist-info/sky-environment-executions-v1.json": json.dumps(
                {
                    "schema_version": 1,
                    "profile": "reviewed_environment_provider_executions_v1",
                    "provider": "installed-provider",
                    "registrations": registrations,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
        }
        record_path = "sky_environment_provider-1.2.3.dist-info/RECORD"
        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\n")
        for path, content in sorted(documents.items()):
            raw = content.encode()
            digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
            writer.writerow([path, "sha256=" + digest, str(len(raw))])
        writer.writerow([record_path, "", ""])
        documents[record_path] = output.getvalue()
        for name, content in documents.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            path.chmod(0o644)
        self.files = tuple(PurePosixPath(value) for value in documents)
        seal_provider(root)

    def locate_file(self, value):
        return self.root / str(value)


class EntryPoint:
    group = ENTRY_POINT_GROUP
    name = "installed-provider"
    value = "sky_env_provider:provide"

    def __init__(self, provider, root, selected=None):
        self.provider = provider
        self.loads = 0
        self.dist = Distribution(root, selected=selected)
        self.module_path = root / "sky_env_provider.py"

    def load(self):
        self.loads += 1
        return self.provider


def add_installer_metadata(entry_point, marker):
    distribution = entry_point.dist
    root = distribution.root
    dist_info = PurePosixPath("sky_environment_provider-1.2.3.dist-info")
    root.chmod(0o700)
    (root / str(dist_info)).chmod(0o700)
    for name, content in (
        ("INSTALLER", "pip\n"),
        ("REQUESTED", ""),
        ("direct_url.json", json.dumps({"url": marker})),
    ):
        relative = dist_info / name
        path = root / str(relative)
        path.write_text(content)
        path.chmod(0o644)
        if relative not in distribution.files:
            distribution.files = (*distribution.files, relative)
    record_path = dist_info / "RECORD"
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for relative in sorted(distribution.files, key=str):
        if relative == record_path:
            continue
        raw = (root / str(relative)).read_bytes()
        digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
        writer.writerow([str(relative), "sha256=" + digest, str(len(raw))])
    writer.writerow([str(record_path), "", ""])
    record = root / str(record_path)
    record.chmod(0o600)
    record.write_text(output.getvalue())
    seal_provider(root)


def test_operator_manifest_and_installed_provider_must_match_exactly(tmp_path, monkeypatch):
    monkeypatch.setattr(__import__("sys"), "dont_write_bytecode", False)
    selected = composition()
    provider = Mock(return_value=(selected,))
    entry_point = EntryPoint(provider, tmp_path / "provider", selected)
    manifest = load_environment_execution_manifest(
        manifest_file(tmp_path, selected, entry_point), workspace="test"
    )

    assert compose_environment_executions(manifest, entry_points=[entry_point]) == (selected,)
    assert __import__("sys").dont_write_bytecode is True
    provider.assert_called_once_with((selected.execution.job.id,))
    assert entry_point.loads == 1

    changed_ref = "EVR-" + "c" * 64
    changed = RegisteredEnvironmentExecutionComposition(
        selected.execution,
        changed_ref,
        Mock(verify=selected.resource_verifier.verify, reference=changed_ref),
        selected.effect_ref,
        selected.effect,
    )
    changed_entry_point = EntryPoint(lambda _selected: (changed,), tmp_path / "changed-provider", selected)
    with pytest.raises(ValueError, match="differs from operator pins"):
        compose_environment_executions(
            load_environment_execution_manifest(
                manifest_file(tmp_path, selected, changed_entry_point), workspace="test"
            ),
            entry_points=[changed_entry_point],
        )


def test_composition_routers_never_select_from_queue_data():
    selected = composition()
    guard, journal = Mock(), Mock()
    resources = RegisteredEnvironmentResourceRouter((selected,))
    effects = RegisteredEnvironmentEffectRouter((selected,))

    resources.verify(selected.execution, guard=guard)
    effects(selected.execution, guard=guard, journal=journal)
    selected.resource_verifier.verify.assert_called_once_with(selected.execution, guard=guard)
    selected.effect.assert_called_once_with(selected.execution, guard=guard, journal=journal)

    other = registered()
    object.__setattr__(other.job, "id", "other-registration")
    with pytest.raises(ValueError, match="registration changed"):
        effects(other, guard=guard, journal=journal)


@pytest.mark.parametrize(
    "change",
    [
        {"workspace": "other"},
        {"provider": "module.path"},
        {"registrations": []},
        {"extra": True},
    ],
)
def test_manifest_rejects_wrong_scope_unknown_fields_and_empty_authority(tmp_path, change):
    selected = composition()
    with pytest.raises(ValueError):
        load_environment_execution_manifest(manifest_file(tmp_path, selected, **change), workspace="test")


@pytest.mark.parametrize("change", ["relative", "symlink", "mode", "noncanonical"])
def test_manifest_requires_one_immutable_canonical_absolute_file(tmp_path, monkeypatch, change):
    selected = composition()
    path = manifest_file(tmp_path, selected)
    requested = path
    if change == "relative":
        monkeypatch.chdir(tmp_path)
        requested = path.name
    elif change == "symlink":
        link = tmp_path / "manifest-link.json"
        link.symlink_to(path)
        requested = link
    elif change == "mode":
        path.chmod(0o666)
    else:
        value = json.loads(path.read_bytes())
        path.write_text(json.dumps(value, indent=2, sort_keys=True))
    with pytest.raises(ValueError, match="manifest"):
        load_environment_execution_manifest(requested, workspace="test")


def test_manifest_descriptor_change_during_read_is_rejected(tmp_path):
    path = manifest_file(tmp_path, composition())
    original = os.read
    changed = False

    def mutate_mode(descriptor, size):
        nonlocal changed
        content = original(descriptor, size)
        if not changed:
            os.fchmod(descriptor, 0o666)
            changed = True
        return content

    with (
        patch("interfaces.environment_execution_registration.os.read", side_effect=mutate_mode),
        pytest.raises(ValueError, match="changed while reading"),
    ):
        load_environment_execution_manifest(path, workspace="test")


def test_provider_discovery_requires_one_installed_entry_point(tmp_path):
    with pytest.raises(ValueError, match="Exactly one"):
        environment_execution_entry_points("installed-provider", entry_points=[])
    duplicate = [
        EntryPoint(Mock(), tmp_path / "provider-one"),
        EntryPoint(Mock(), tmp_path / "provider-two"),
    ]
    with pytest.raises(ValueError, match="Exactly one"):
        environment_execution_entry_points("installed-provider", entry_points=duplicate)


def test_cli_check_config_does_not_import_provider_or_call_aws_or_database(tmp_path, monkeypatch, capsys):
    selected = composition()
    entry_point = EntryPoint(
        Mock(side_effect=AssertionError("provider called")), tmp_path / "provider", selected
    )
    path = manifest_file(tmp_path, selected, entry_point)
    ca = tmp_path / "ca.pem"
    ca.write_text("configuration-only")
    values = {
        "SKY_DATABASE_HOST": "db.example",
        "SKY_DATABASE_NAME": "sky",
        "SKY_DATABASE_SECRET_ARN": "arn:aws:secretsmanager:ap-northeast-2:977889523182:secret:test",
        "SKY_DATABASE_SSLROOTCERT": str(ca),
        "SKY_AWS_REGION": "ap-northeast-2",
        "SKY_AWS_ACCOUNT_ID": "977889523182",
        "SKY_STATE_WORKSPACE": "test",
        "SKY_JOB_QUEUE_URL": "https://sqs.ap-northeast-2.amazonaws.com/977889523182/jobs.fifo",
        "SKY_ENVIRONMENT_EXECUTION_QUEUE_URL": "https://sqs.ap-northeast-2.amazonaws.com/977889523182/environment.fifo",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    with (
        patch(
            "interfaces.environment_execution_registration.metadata.entry_points",
            return_value=[entry_point],
        ),
        patch("interfaces.shared_database_worker.load_hosted_identity", return_value=Mock()),
        patch("boto3.client", side_effect=AssertionError("AWS called")),
        patch(
            "adapters.state.postgres.RotatingDatabaseConnection",
            side_effect=AssertionError("DB called"),
        ),
    ):
        main(
            [
                "worker",
                "--mode",
                "environment-execution",
                "--environment-execution-config",
                str(path),
                "--check-config",
            ]
        )
    assert entry_point.loads == 0
    assert "provider code, AWS and DB were not called" in capsys.readouterr().out


def test_cli_composes_only_pinned_provider_and_runs_one_hosted_delivery(tmp_path, monkeypatch, capsys):
    selected = composition()
    entry_point = EntryPoint(Mock(return_value=(selected,)), tmp_path / "provider", selected)
    path = manifest_file(tmp_path, selected, entry_point)
    ca = tmp_path / "ca.pem"
    ca.write_text("runtime-test")
    for name, value in {
        "SKY_DATABASE_HOST": "db.example",
        "SKY_DATABASE_NAME": "sky",
        "SKY_DATABASE_SECRET_ARN": "arn:aws:secretsmanager:ap-northeast-2:977889523182:secret:test",
        "SKY_DATABASE_SSLROOTCERT": str(ca),
        "SKY_AWS_REGION": "ap-northeast-2",
        "SKY_AWS_ACCOUNT_ID": "977889523182",
        "SKY_STATE_WORKSPACE": "test",
        "SKY_JOB_QUEUE_URL": "https://sqs.ap-northeast-2.amazonaws.com/977889523182/jobs.fifo",
        "SKY_ENVIRONMENT_EXECUTION_QUEUE_URL": "https://sqs.ap-northeast-2.amazonaws.com/977889523182/environment.fifo",
    }.items():
        monkeypatch.setenv(name, value)
    store = Mock(workspace="test")
    queue = Mock()
    admission = Mock()

    with (
        patch(
            "interfaces.environment_execution_registration.metadata.entry_points",
            return_value=[entry_point],
        ),
        patch("interfaces.shared_database_worker.load_hosted_identity", return_value=Mock()),
        patch("adapters.aws.job_queue.SqsOperationQueue", return_value=queue),
        patch("adapters.state.operations.PostgresOperationStore", return_value=store),
        patch("adapters.state.postgres.RotatingDatabaseConnection") as connection,
        patch("adapters.state.readiness.check_database_ready") as ready,
        patch("adapters.state.deployment_admission.PostgresDeploymentAdmission"),
        patch(
            "adapters.state.environment_admission.PostgresEnvironmentExecutionAdmission",
            return_value=admission,
        ),
        patch(
            "interfaces.environment_execution_consumer.run_reviewed_environment_consumer",
            return_value="idle",
        ) as run,
    ):
        main(
            [
                "worker",
                "--mode",
                "environment-execution",
                "--environment-execution-config",
                str(path),
                "--once",
            ]
        )

    assert entry_point.loads == 1
    entry_point.provider.assert_called_once_with((selected.execution.job.id,))
    ready.assert_called_once_with(connection.return_value, operations=True)
    admission.check_ready.assert_called_once_with()
    run.assert_called_once()
    assert run.call_args.kwargs == {"once": True, "wait_seconds": 5}
    assert "Reviewed environment consumer: idle" in capsys.readouterr().out


def test_provider_artifact_is_verified_before_and_after_import(tmp_path):
    selected = composition()
    entry_point = EntryPoint(Mock(return_value=(selected,)), tmp_path / "provider", selected)
    manifest = load_environment_execution_manifest(
        manifest_file(tmp_path, selected, entry_point), workspace="test"
    )
    entry_point.module_path.chmod(0o600)
    entry_point.module_path.write_text("changed before import\n")
    entry_point.module_path.chmod(0o400)
    with pytest.raises(ValueError, match="RECORD digest|differs from operator pin"):
        compose_environment_executions(manifest, entry_points=[entry_point])
    assert entry_point.loads == 0

    after = EntryPoint(Mock(), tmp_path / "after-provider", selected)

    def change_after_import(_selected):
        after.module_path.chmod(0o600)
        after.module_path.write_text("changed during provider load\n")
        after.module_path.chmod(0o400)
        return (selected,)

    after.provider.side_effect = change_after_import
    manifest = load_environment_execution_manifest(manifest_file(tmp_path, selected, after), workspace="test")
    with pytest.raises(ValueError, match="RECORD digest|differs from operator pin"):
        compose_environment_executions(manifest, entry_points=[after])


def test_provider_artifact_rejects_writable_or_unbounded_package(tmp_path):
    entry_point = EntryPoint(Mock(), tmp_path / "provider")
    entry_point.module_path.chmod(0o666)
    with pytest.raises(ValueError, match="Immutable bounded"):
        attest_environment_execution_provider(entry_point)
    entry_point.module_path.chmod(0o400)
    entry_point.dist.files = (*entry_point.dist.files, PurePosixPath("../outside.py"))
    with pytest.raises(ValueError, match="Canonical provider distribution path"):
        attest_environment_execution_provider(entry_point)


@pytest.mark.parametrize("field", ["digest", "size"])
def test_provider_artifact_requires_record_to_match_installed_files(tmp_path, field):
    entry_point = EntryPoint(Mock(), tmp_path / "provider")
    record = entry_point.dist.root / "sky_environment_provider-1.2.3.dist-info/RECORD"
    rows = list(csv.reader(io.StringIO(record.read_text())))
    if field == "digest":
        rows[0][1] = "sha256=" + "A" * 43
    else:
        rows[0][2] = str(int(rows[0][2]) + 1)
    output = io.StringIO(newline="")
    csv.writer(output, lineterminator="\n").writerows(rows)
    record.chmod(0o600)
    record.write_text(output.getvalue())
    record.chmod(0o400)
    with pytest.raises(ValueError, match="RECORD digest or size"):
        attest_environment_execution_provider(entry_point)


def test_provider_artifact_ignores_installer_location_metadata(tmp_path):
    one = EntryPoint(Mock(), tmp_path / "one")
    two = EntryPoint(Mock(), tmp_path / "two")
    add_installer_metadata(one, "file:///private/build/one/provider.whl")
    add_installer_metadata(two, "file:///different/image/path/provider.whl")
    assert attest_environment_execution_provider(one) == attest_environment_execution_provider(two)


def test_provider_artifact_rejects_bytecode_cache(tmp_path):
    entry_point = EntryPoint(Mock(), tmp_path / "provider")
    cache = entry_point.dist.root / "__pycache__"
    entry_point.dist.root.chmod(0o700)
    cache.mkdir()
    bytecode = cache / "sky_env_provider.cpython-314.pyc"
    bytecode.write_bytes(b"executable-bytecode")
    relative = PurePosixPath(bytecode.relative_to(entry_point.dist.root).as_posix())
    entry_point.dist.files = (*entry_point.dist.files, relative)
    add_installer_metadata(entry_point, "file:///provider.whl")
    with pytest.raises(ValueError, match="bytecode caches are forbidden"):
        attest_environment_execution_provider(entry_point)


def test_provider_inspection_prints_approval_pin_without_import(tmp_path, capsys):
    entry_point = EntryPoint(Mock(side_effect=AssertionError("provider imported")), tmp_path / "provider")
    expected = attest_environment_execution_provider(entry_point)
    with patch(
        "interfaces.environment_execution_registration.metadata.entry_points",
        return_value=[entry_point],
    ):
        inspect_provider(["--provider", "installed-provider"])
    assert entry_point.loads == 0
    assert json.loads(capsys.readouterr().out) == {
        "schema_version": 1,
        "profile": "reviewed_environment_provider_artifact_v1",
        **expected.document(),
    }


def test_manifest_generator_uses_secret_free_descriptor_without_import(tmp_path, capsys):
    selected = composition()
    entry_point = EntryPoint(
        Mock(side_effect=AssertionError("provider imported")), tmp_path / "provider", selected
    )
    with patch(
        "interfaces.environment_execution_registration.metadata.entry_points",
        return_value=[entry_point],
    ):
        render_manifest(["--provider", "installed-provider", "--workspace", "test"])
    document = json.loads(capsys.readouterr().out)
    expected = render_environment_execution_manifest("installed-provider", "test", entry_points=[entry_point])
    assert document == expected
    assert document["registrations"] == [
        {
            "registration_id": selected.execution.job.id,
            "execution_revision": selected.execution.revision,
            "application_id": selected.execution.job.transfer.source.application_id,
            "resource_verifier_ref": selected.resource_verifier_ref,
            "effect_ref": selected.effect_ref,
        }
    ]
    assert entry_point.loads == 0


def test_provider_descriptor_must_be_canonical_even_with_matching_record(tmp_path):
    selected = composition()
    entry_point = EntryPoint(
        Mock(side_effect=AssertionError("provider imported")), tmp_path / "provider", selected
    )
    descriptor = next(
        entry_point.dist.root / str(value)
        for value in entry_point.dist.files
        if str(value).endswith(".dist-info/sky-environment-executions-v1.json")
    )
    descriptor.chmod(0o600)
    descriptor.write_text(json.dumps(json.loads(descriptor.read_bytes()), indent=2, sort_keys=True))
    add_installer_metadata(entry_point, "file:///reviewed-provider.whl")
    with pytest.raises(ValueError, match="Canonical provider execution descriptor"):
        render_environment_execution_manifest("installed-provider", "test", entry_points=[entry_point])
    assert entry_point.loads == 0


def test_manifest_and_provider_descriptor_must_match_before_import(tmp_path):
    selected = composition()
    entry_point = EntryPoint(Mock(return_value=(selected,)), tmp_path / "provider", selected)
    registration = {
        "registration_id": selected.execution.job.id,
        "execution_revision": selected.execution.revision,
        "application_id": selected.execution.job.transfer.source.application_id,
        "resource_verifier_ref": selected.resource_verifier_ref,
        "effect_ref": "EEF-" + "c" * 64,
    }
    manifest = load_environment_execution_manifest(
        manifest_file(tmp_path, selected, entry_point, registrations=[registration]),
        workspace="test",
    )
    with pytest.raises(ValueError, match="descriptor differs"):
        compose_environment_executions(manifest, entry_points=[entry_point])
    assert entry_point.loads == 0


@pytest.mark.parametrize("mode", ["outbox", "operating-review", "dedicated-database"])
def test_environment_manifest_cannot_activate_another_worker_mode(tmp_path, mode):
    selected = composition()
    with pytest.raises(SystemExit) as error:
        main(
            [
                "worker",
                "--mode",
                mode,
                "--environment-execution-config",
                str(manifest_file(tmp_path, selected)),
                "--check-config",
            ]
        )
    assert error.value.code == 2
