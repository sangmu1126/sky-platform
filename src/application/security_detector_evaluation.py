"""Keyless replay measurements for the exact forbidden-Secret detector contract.

Synthetic provider replay, not a population false-positive rate or live attack.
No AWS calls, model, notifications, holds or user-supplied log authorization.
"""

import json
from datetime import UTC, datetime, timedelta
from uuid import NAMESPACE_URL, uuid5

from adapters.aws.security_monitor import CloudTrailSecretAccessMonitor, SecretAccessRegistration


class _FixtureClient:
    def __init__(self, documents, incomplete=False):
        self.documents, self.incomplete = documents, incomplete

    def get_caller_identity(self):
        return {"Account": "123456789012"}

    def lookup_events(self, **_):
        response = {"Events": [{"CloudTrailEvent": json.dumps(value)} for value in self.documents]}
        if self.incomplete:
            response["NextToken"] = "synthetic-incomplete-page"
        return response


class _FixtureSession:
    def __init__(self, documents, incomplete=False):
        self.fixture = _FixtureClient(documents, incomplete)

    def client(self, name, **_):
        if name not in {"sts", "cloudtrail"}:
            raise AssertionError("Replay must not create cloud mutation/notification clients")
        return self.fixture


def evaluate_secret_detector(*, repetitions=20):
    if type(repetitions) is not int or not 1 <= repetitions <= 100:
        raise ValueError("Bounded replay repetitions required")
    now = datetime(2026, 10, 30, 0, 5, tzinfo=UTC)
    registration = SecretAccessRegistration(
        "123456789012",
        "ap-northeast-2",
        "arn:aws:iam::123456789012:role/sky-app-a",
        "AROA" + "A" * 17,
        ("arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:forbidden-AbCdEf",),
    )
    totals = {
        "true_positive": 0,
        "true_negative": 0,
        "false_positive": 0,
        "false_negative": 0,
        "incomplete_not_treated_as_healthy": 0,
        "duplicate_events_deduplicated": 0,
    }
    groups = {}
    contract_failures = []
    for kind in (
        "allowed_secret",
        "denied_secret",
        "other_role",
        "recreated_role",
        "other_region",
        "other_account",
        "application_log",
        "forbidden_read",
        "duplicate_read",
        "truncated_pages",
        "malformed_event",
    ):
        samples = []
        for index in range(repetitions):
            event = {
                "eventSource": "secretsmanager.amazonaws.com",
                "eventName": "GetSecretValue",
                "recipientAccountId": registration.account_id,
                "awsRegion": registration.region,
                "eventID": str(uuid5(NAMESPACE_URL, "sky-evaluation:" + kind + ":" + str(index))),
                "eventTime": (now - timedelta(seconds=30)).isoformat(),
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": registration.role_id + ":synthetic",
                    "sessionContext": {"sessionIssuer": {"arn": registration.role_arn}},
                },
                "requestParameters": {"secretId": registration.forbidden_secrets[0]},
            }
            expected = kind in {"forbidden_read", "duplicate_read"}
            if kind == "allowed_secret":
                event["requestParameters"]["secretId"] = (
                    "arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:allowed-AbCdEf"
                )
            elif kind == "denied_secret":
                event["errorCode"] = "AccessDenied"
            elif kind == "other_role":
                event["userIdentity"]["sessionContext"]["sessionIssuer"]["arn"] = (
                    registration.role_arn + "-foreign"
                )
            elif kind == "recreated_role":
                event["userIdentity"]["principalId"] = "AROA" + "B" * 17 + ":synthetic"
            elif kind == "other_region":
                event["awsRegion"] = "us-east-1"
            elif kind == "other_account":
                event["recipientAccountId"] = "999999999999"
            elif kind == "application_log":
                event["eventSource"] = "untrusted-app-log"
            elif kind == "malformed_event":
                event["userIdentity"] = "untrusted-malformed-object"
            documents = [event, event] if kind == "duplicate_read" else [event]
            monitor = CloudTrailSecretAccessMonitor(
                registration, session=_FixtureSession(documents, kind == "truncated_pages")
            )
            try:
                result = monitor.observe(now=now.isoformat())
            except ValueError:
                result = {
                    "collection_complete": False,
                    "matching_successful_forbidden_reads": [],
                    "absence_of_compromise_proven": False,
                }
            actual = bool(result["matching_successful_forbidden_reads"])
            if kind in {"truncated_pages", "malformed_event"}:
                if result["collection_complete"] is False and result["absence_of_compromise_proven"] is False:
                    totals["incomplete_not_treated_as_healthy"] += 1
                else:
                    contract_failures.append(
                        {"scenario": kind, "case": index, "reason": "unavailable_collection_claimed_healthy"}
                    )
            else:
                field = (
                    ("true_positive" if expected else "false_positive")
                    if actual
                    else ("false_negative" if expected else "true_negative")
                )
                totals[field] += 1
                if kind == "duplicate_read":
                    if len(result["matching_successful_forbidden_reads"]) == 1:
                        totals["duplicate_events_deduplicated"] += 1
                    else:
                        contract_failures.append(
                            {"scenario": kind, "case": index, "reason": "duplicate_detection_invalid"}
                        )
            samples.append(
                {
                    "expected_critical": expected,
                    "actual_critical": actual,
                    "collection_complete": result["collection_complete"],
                }
            )
        groups[kind] = samples
    return {
        "version": 1,
        "dataset": "synthetic-read-only-provider-replay",
        "live_cloud_calls": False,
        "holds_or_releases_executed": False,
        "population_detection_or_sla_claimed": False,
        "repetitions_per_scenario": repetitions,
        "scenario_count": len(groups),
        "totals": totals,
        "scenarios": groups,
        "contract_failures": contract_failures,
        "passed": totals["false_positive"] == totals["false_negative"] == 0 and not contract_failures,
    }
