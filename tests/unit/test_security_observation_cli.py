import json
import stat
from unittest.mock import Mock, patch

import pytest

from scripts.observe_security import collect, main, write_private


def registration(tmp_path):
    path = tmp_path / "registration.json"
    path.write_text(
        json.dumps(
            {
                "account_id": "123456789012",
                "region": "ap-northeast-2",
                "role_arn": "arn:aws:iam::123456789012:role/registered-app",
                "role_id": "AROA" + "A" * 17,
                "forbidden_secrets": [
                    "arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:other-app-test01"
                ],
            }
        )
    )
    return path


def test_read_only_observation_is_not_security_clearance(tmp_path):
    with patch("scripts.observe_security.CloudTrailSecretAccessMonitor") as monitor:
        monitor.return_value.observe.return_value = {
            "successful_forbidden_reads": [],
            "no_compromise_proven": False,
        }
        report = collect(registration(tmp_path), now="2026-10-29T00:00:00Z", session=Mock())
        assert report["operator_review_required"] and not report["cloud_changed"]
        assert not report["security_hold_changed"]
        monitor.return_value.observe.assert_called_once_with(now="2026-10-29T00:00:00Z")
    output = tmp_path / "report.json"
    write_private(output, report)
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        write_private(output, report)


def test_duplicate_registration_is_refused_before_cloud_clients(tmp_path):
    path = tmp_path / "registration.json"
    path.write_text('{"account_id":"one","account_id":"two"}')
    with (
        patch("scripts.observe_security.CloudTrailSecretAccessMonitor") as monitor,
        pytest.raises(ValueError),
    ):
        collect(path, now="2026-10-29T00:00:00Z")
    monitor.assert_not_called()


def test_output_symlink_cannot_overwrite_another_file(tmp_path):
    original, link = tmp_path / "original", tmp_path / "link"
    original.write_text("untouched")
    link.symlink_to(original)
    with pytest.raises(OSError):
        write_private(link, {"observation": "test"})
    assert original.read_text() == "untouched"


def test_cloud_failure_exits_without_sensitive_diagnostic_or_report(tmp_path, capsys):
    output = tmp_path / "out.json"
    with (
        patch("scripts.observe_security.collect", side_effect=OSError("synthetic-private-canary")),
        pytest.raises(SystemExit),
    ):
        main(["--registration", str(registration(tmp_path)), "--output", str(output)])
    assert "synthetic-private-canary" not in capsys.readouterr().err
    assert not output.exists()
