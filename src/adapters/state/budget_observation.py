"""Publish bounded quota counters from the real reservation ledger, not app logs.

This exporter never settles/refunds a reservation, changes a limit, or estimates
money. A separate read-only AWS collector consumes these operational metrics.
"""

import hashlib
import json
import re
from datetime import datetime

from adapters.state.effect_budget import EffectBudgetPolicy

NAMESPACE = "Sky/OperationalBudget"


class BudgetUsageExporter:
    def __init__(self, connection, policy, client, *, workspace):
        if not isinstance(policy, EffectBudgetPolicy) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", workspace):
            raise ValueError("Current registered ledger policy and workspace required")
        self.connection, self.policy, self.client, self.workspace = connection, policy, client, workspace
        self.document = json.loads(policy.document)
        self.digest = hashlib.sha256(policy.document.encode()).hexdigest()

    def publish(self):
        with self.connection() as db:
            db.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            db.execute("SET LOCAL statement_timeout='5s'")
            now, window = db.execute(
                "SELECT clock_timestamp(),date_trunc('hour',clock_timestamp())"
            ).fetchone()
            if now.tzinfo is None or now >= datetime.fromisoformat(self.document["expires_at"]):
                raise ValueError("Quota observation approval expired")
            existing = db.execute(
                "SELECT policy_digest FROM sky_state.effect_budget_windows WHERE workspace=%s AND window_start=%s",
                (self.workspace, window),
            ).fetchone()
            if existing is not None and existing != (self.digest,):
                raise ValueError("Current ledger policy differs from operator approval")
            # Current-hour effects plus any retained commitments. No row contains
            # credentials, source code, SQL text or user-supplied log messages.
            rows = db.execute(
                "SELECT organization_id,user_id,application_id,reserved,window_start FROM sky_state.effect_budget_reservations WHERE workspace=%s ORDER BY created_at DESC LIMIT 1001",
                (self.workspace,),
            ).fetchall()
            if len(rows) > 1000:
                raise ValueError(
                    "Ledger observation exceeds bounded inventory; explicit reconciliation required"
                )
            totals = {
                ("global", "global", "global"): {metric: 0 for metric in self.document["limits"]["global"]}
            }
            for org, user, app, reserved, stamp in rows:
                if not all(
                    isinstance(x, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", x) for x in (org, user, app)
                ):
                    raise ValueError("Ledger identity outside registered quota contract")
                scopes = [("global", "global", "global"), ("organization", org, org), ("user", org, user)]
                if "application" in self.document["limits"]:
                    scopes.append(("application", org, app))
                for scope in scopes:
                    bucket = totals.setdefault(
                        scope, {metric: 0 for metric in self.document["limits"][scope[0]]}
                    )
                    for metric in bucket:
                        value = reserved.get(metric)
                        if type(value) is not int or not 0 <= value <= 10**15:
                            raise ValueError("Malformed authoritative reservation vector")
                        if stamp == window or metric in {"active_resources", "retained_microusd"}:
                            bucket[metric] += value
            if len(totals) > 64:
                raise ValueError("Bounded quota metric inventory required")
            points = []
            for (scope, org, identity), values in sorted(totals.items()):
                for metric, used in sorted(values.items()):
                    dimensions = [
                        {"Name": k, "Value": v}
                        for k, v in {
                            "Workspace": self.workspace,
                            "Organization": org,
                            "Scope": scope,
                            "Identity": identity,
                            "Metric": metric,
                            "PolicyDigest": self.digest,
                        }.items()
                    ]
                    for name, value in [
                        ("ReservedUsage", used),
                        ("ApprovedLimit", self.document["limits"][scope][metric]),
                    ]:
                        points.append(
                            {"MetricName": name, "Dimensions": dimensions, "Timestamp": now, "Value": value}
                        )
        if len(points) > 1000:
            raise ValueError("Quota metrics exceed bounded publish batch")
        self.client.put_metric_data(Namespace=NAMESPACE, MetricData=points)
        return {
            "published_metrics": len(points),
            "policy_digest": self.digest,
            "money_estimate": False,
            "limits_changed": False,
        }

    def run(self, stop):
        while not stop.is_set():
            try:
                self.publish()
            except Exception:  # noqa: BLE001 -- never print private SQL/provider diagnostics
                print("Budget observation unavailable; no fresh metric published.", flush=True)
            if stop.wait(60):
                break
