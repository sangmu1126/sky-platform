"""Durable upper-bound reservations before external effects, not a billing system.

Operator policy supplies identical limits for every replica. Unknown outcomes keep
their entire reservation. No elapsed-time refund, caller usage settlement or
price inference is allowed. Reservations and external intent share a transaction.
Limits govern the hour of admission, not ongoing resource charges in later hours.
This cannot replace active-resource budgets, provider billing or cost settlement.
"""

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime


class EffectBudgetExceeded(ValueError):
    pass


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate budget policy field")
        value[key] = item
    return value


def _vector(value):
    if (not isinstance(value, dict) or not value or len(value) > 8
            or any(not isinstance(k, str) or not re.fullmatch(r"[a-z][a-z_]{0,39}", k)
                   or type(v) is not int or not 0 <= v <= 10**15 for k, v in value.items())):
        raise ValueError("Bounded integer budget vector required")
    return dict(value)


@dataclass(frozen=True)
class EffectBudgetPolicy:
    document: str

    @classmethod
    def from_environment(cls, environment):
        raw = environment.get("SKY_EFFECT_BUDGET_JSON")
        required = environment.get("SKY_REQUIRE_EFFECT_BUDGETS", "false")
        if required not in {"true", "false"}:
            raise ValueError("Explicit effect budget requirement required")
        if raw is None:
            if required == "true":
                raise ValueError("Required operator effect budget is missing")
            return None
        if not isinstance(raw, str) or len(raw) > 16384:
            raise ValueError("Bounded operator effect budget required")
        policy = json.loads(raw, object_pairs_hook=_unique)
        if (not isinstance(policy, dict) or set(policy) != {"version", "expires_at", "source", "limits", "effects"}
                or type(policy["version"]) is not int or policy["version"] != 1
                or not isinstance(policy["source"], str) or not 1 <= len(policy["source"]) <= 256
                or not isinstance(policy["limits"], dict)
                or set(policy["limits"]) != {"global", "organization", "user"}
                or not isinstance(policy["effects"], dict) or not 1 <= len(policy["effects"]) <= 32):
            raise ValueError("Exact operator effect budget required")
        expires = datetime.fromisoformat(policy["expires_at"])
        if expires.tzinfo is None or expires.utcoffset() is None:
            raise ValueError("Budget policy expiry requires timezone")
        limits = {scope: _vector(values) for scope, values in policy["limits"].items()}
        keys = set(limits["global"])
        if any(set(v) != keys for v in limits.values()):
            raise ValueError("Budget dimensions must match")
        if any(not 0 < limits["user"][k] <= limits["organization"][k] <= limits["global"][k] for k in keys):
            raise ValueError("User/organization/global budget hierarchy required")
        for kind, values in policy["effects"].items():
            if not isinstance(kind, str) or not re.fullmatch(r"[a-z][a-z_]{0,63}", kind):
                raise ValueError("Explicit effect kind required")
            if set(_vector(values)) != keys or not any(values.values()):
                raise ValueError("Every effect must reserve every budget dimension")
        return cls(json.dumps(policy, sort_keys=True, separators=(",", ":")))

    @staticmethod
    def initialize(connection):
        connection.execute("""CREATE TABLE IF NOT EXISTS sky_state.effect_budget_windows (
            workspace text NOT NULL, window_start timestamptz NOT NULL, policy_digest text NOT NULL,
            PRIMARY KEY(workspace,window_start))""")
        connection.execute("""CREATE TABLE IF NOT EXISTS sky_state.effect_budget_reservations (
            workspace text NOT NULL, effect_key text NOT NULL, window_start timestamptz NOT NULL,
            organization_id text NOT NULL, user_id text NOT NULL, binding_digest text NOT NULL,
            reserved jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY(workspace,effect_key))""")
        connection.execute("""CREATE INDEX IF NOT EXISTS effect_budget_window_idx
            ON sky_state.effect_budget_reservations(workspace,window_start)""")

    def reserve(self, connection, *, workspace, effect_key, organization_id, user_id, kind, binding):
        if connection.execute("SHOW transaction_isolation").fetchone() != ("read committed",):
            raise ValueError("Budget reservation requires read committed")
        for value in (workspace, organization_id, user_id):
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
                raise ValueError("Trusted budget owner required")
        if not isinstance(effect_key, str) or not re.fullmatch(r"[A-Za-z0-9_:-]{1,160}", effect_key):
            raise ValueError("Stable budget effect identity required")
        policy = json.loads(self.document)
        # Serialize all three scopes together; policy changes within an hour fail
        # closed instead of resetting counters or letting replicas pick a budget.
        lock = int.from_bytes(hashlib.sha256(("effect-budget:" + workspace).encode()).digest()[:8], "big", signed=True)
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (lock,))
        now, window = connection.execute("""WITH moment AS MATERIALIZED (SELECT clock_timestamp() AS stamp)
            SELECT stamp,date_trunc('hour',stamp) FROM moment""").fetchone()
        if now >= datetime.fromisoformat(policy["expires_at"]):
            raise EffectBudgetExceeded("Operator budget policy has expired")
        if kind not in policy["effects"]:
            raise EffectBudgetExceeded("External effect has no trusted cost/resource reservation")
        document = json.dumps({"owner": [organization_id, user_id], "kind": kind, "binding": binding},
                              sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(document) > 131072:
            raise ValueError("Bounded external effect binding required")
        digest = hashlib.sha256(document.encode()).hexdigest()
        existing = connection.execute("""SELECT binding_digest FROM sky_state.effect_budget_reservations
            WHERE workspace=%s AND effect_key=%s""", (workspace, effect_key)).fetchone()
        if existing:
            if existing[0] != digest:
                raise ValueError("Budget effect identity was rebound")
            return False
        policy_digest = hashlib.sha256(self.document.encode()).hexdigest()
        connection.execute("""INSERT INTO sky_state.effect_budget_windows VALUES(%s,%s,%s)
            ON CONFLICT DO NOTHING""", (workspace, window, policy_digest))
        if connection.execute("""SELECT policy_digest FROM sky_state.effect_budget_windows
            WHERE workspace=%s AND window_start=%s""", (workspace, window)).fetchone() != (policy_digest,):
            raise EffectBudgetExceeded("Budget policy changed within an active window")
        requested = policy["effects"][kind]
        for scope in ("global", "organization", "user"):
            extra, parameters = "", [workspace, window]
            if scope in {"organization", "user"}:
                extra += " AND organization_id=%s"
                parameters.append(organization_id)
            if scope == "user":
                extra += " AND user_id=%s"
                parameters.append(user_id)
            for metric, amount in requested.items():
                total = connection.execute("""SELECT coalesce(sum((reserved->>%s)::bigint),0)
                    FROM sky_state.effect_budget_reservations WHERE workspace=%s AND window_start=%s""" + extra,
                    [metric, *parameters]).fetchone()[0]
                if total + amount > policy["limits"][scope][metric]:
                    raise EffectBudgetExceeded("External effect budget exhausted")
        connection.execute("""INSERT INTO sky_state.effect_budget_reservations
            (workspace,effect_key,window_start,organization_id,user_id,binding_digest,reserved)
            VALUES(%s,%s,%s,%s,%s,%s,%s::jsonb)""",
            (workspace, effect_key, window, organization_id, user_id, digest, json.dumps(requested)))
        return True
