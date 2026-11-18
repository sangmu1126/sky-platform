"""Collect exact-plan inventories without granting execution or migration approval."""

import hashlib
import json
from dataclasses import asdict
from datetime import timedelta

from domain.database_inventory import (
    DatabaseInventory,
    DatabaseInventoryUnavailable,
    DatabaseResourceEvidence,
    aware_time,
)
from domain.database_migration import DatabaseLocation, DatabasePlacement, MigrationSafetyPolicy
from engine.database_migration import plan_database_migration


class DatabaseMigrationPreflight:
    def __init__(self, source_reader, target_reader, *, clock, max_age_seconds):
        if type(max_age_seconds) is not int or not 1 <= max_age_seconds <= 300:
            raise ValueError("Explicit bounded inventory freshness required")
        self.readers = {"source": source_reader, "target": target_reader}
        self.clock, self.max_age = clock, max_age_seconds

    def inspect(self, source, target, policy, *, source_revision):
        plan = plan_database_migration(source, target, policy, source_revision=source_revision)
        inventories, checks = {}, []
        for name, placement in (("source", source), ("target", target)):
            try:
                observation = self.readers[name].inspect(placement, plan_id=plan["plan_id"])
            except DatabaseInventoryUnavailable:
                checks.append({"name": name + "_inventory", "status": "unverified", "reason": "unavailable"})
                continue
            if not isinstance(observation, DatabaseInventory) or (
                observation.plan_id != plan["plan_id"] or observation.placement != placement
            ):
                checks.append(
                    {"name": name + "_inventory", "status": "blocked", "reason": "binding_mismatch"}
                )
                continue
            inventories[name] = observation

        now = self.clock()
        aware_time(now)
        for name, observation in list(inventories.items()):
            times = (observation.observed_at, observation.resource.observed_at)
            if any(not 0 <= (now - at).total_seconds() <= self.max_age for at in times):
                checks.append(
                    {"name": name + "_inventory", "status": "unverified", "reason": "stale_or_future"}
                )
                del inventories[name]
            else:
                checks.append({"name": name + "_inventory", "status": "verified", "reason": None})

        if len(inventories) == 2:
            src, dst = inventories["source"], inventories["target"]
            conditions = {
                "declared_versions": (
                    src.server_version_num // 10000 == source.postgres_major
                    and dst.server_version_num // 10000 == target.postgres_major
                    and source.postgres_major == target.postgres_major
                ),
                "schema_and_extensions": (
                    src.schema_status == dst.schema_status == "supported"
                    and src.extensions == dst.extensions
                    and set(src.extensions) <= {("plpgsql", "1.0")}
                    and 1 <= src.table_count <= 100
                    and dst.table_count == 0
                ),
                "database_locale": (src.encoding, src.collation, src.ctype)
                == (dst.encoding, dst.collation, dst.ctype),
            }
            checks.extend(
                {
                    "name": key,
                    "status": "verified" if value else "blocked",
                    "reason": None if value else "incompatible",
                }
                for key, value in conditions.items()
            )
            verified = {"source_target_ownership", "source_inventory"}
            if all(conditions.values()):
                verified.add("supported_schema_and_extensions")
            for gate in plan["required_gates"]:
                if gate["name"] in verified:
                    gate["status"] = "verified"

        failures = [check for check in checks if check["status"] != "verified"]
        plan["blockers"].extend("preflight_" + c["name"] + "_" + c["reason"] for c in failures)
        plan["preflight"] = {
            "plan_id": plan["plan_id"],
            "status": "blocked" if failures else "passed",
            "scope": "registered_resource_and_read_only_metadata_only",
            "observed_at": now.isoformat(),
            "max_age_seconds": self.max_age,
            "expires_at": (
                min(
                    at
                    for observation in inventories.values()
                    for at in (observation.observed_at, observation.resource.observed_at)
                )
                + timedelta(seconds=self.max_age)
            ).isoformat()
            if not failures
            else None,
            "checks": checks,
            "inventories": {name: self._document(value) for name, value in inventories.items()},
        }
        encoded = json.dumps(plan["preflight"], sort_keys=True, separators=(",", ":")).encode()
        plan["preflight"]["evidence_id"] = "DBI-" + hashlib.sha256(encoded).hexdigest()
        return plan

    @staticmethod
    def _document(observation):
        document = asdict(observation)
        document["observed_at"] = observation.observed_at.isoformat()
        document["resource"]["observed_at"] = observation.resource.observed_at.isoformat()
        return document


def validate_preflight_report(report):
    """Validate persisted internal output, not authenticate a caller's JSON proof.

    The HTTP boundary must accept review IDs, never a submitted report. A hash
    detects corruption but is not a signature or an inventory authority.
    """
    from datetime import datetime
    from types import SimpleNamespace

    try:
        encoded = json.dumps(
            report, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        if len(encoded.encode()) > 65536:
            raise ValueError("Oversized report")
        document = json.loads(encoded)

        def placement(value):
            return DatabasePlacement(**{**value, "location": DatabaseLocation(**value["location"])})

        source, target = (placement(document[name]) for name in ("source", "target"))
        policy = MigrationSafetyPolicy(**document["safety_policy"])
        base = plan_database_migration(source, target, policy, source_revision=document["source_revision"])
        if set(document) != set(base) | {"preflight"}:
            raise ValueError("Unexpected report fields")
        for key in set(base) - {"required_gates", "blockers"}:
            if json.dumps(document[key], sort_keys=True) != json.dumps(base[key], sort_keys=True):
                raise ValueError("Plan changed")
        observation = document["preflight"]
        if set(observation) != {
            "plan_id",
            "status",
            "scope",
            "observed_at",
            "max_age_seconds",
            "expires_at",
            "checks",
            "inventories",
            "evidence_id",
        }:
            raise ValueError("Unexpected observation fields")
        if set(observation["inventories"]) - {"source", "target"}:
            raise ValueError("Unexpected inventory endpoint")
        unsigned = {k: v for k, v in observation.items() if k != "evidence_id"}
        digest = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if observation["evidence_id"] != "DBI-" + digest or observation["plan_id"] != base["plan_id"]:
            raise ValueError("Evidence changed")
        if observation["scope"] != "registered_resource_and_read_only_metadata_only":
            raise ValueError("Unexpected evidence scope")
        age = observation["max_age_seconds"]
        if type(age) is not int or not 1 <= age <= 300:
            raise ValueError("Invalid evidence freshness")
        checks = observation["checks"]
        allowed = {
            "source_inventory",
            "target_inventory",
            "declared_versions",
            "schema_and_extensions",
            "database_locale",
        }
        if not isinstance(checks, list) or not 2 <= len(checks) <= 5:
            raise ValueError("Invalid observation checks")
        names = []
        for check in checks:
            if set(check) != {"name", "status", "reason"} or check["name"] not in allowed:
                raise ValueError("Unexpected observation check")
            expected_reason = {
                "verified": {None},
                "unverified": {"unavailable", "stale_or_future"},
                "blocked": {"binding_mismatch", "incompatible"},
            }
            if (
                check["status"] not in expected_reason
                or check["reason"] not in expected_reason[check["status"]]
            ):
                raise ValueError("Invalid observation reason")
            names.append(check["name"])
        if len(names) != len(set(names)) or not {"source_inventory", "target_inventory"} <= set(names):
            raise ValueError("Duplicate or missing observation checks")
        failures = [c for c in checks if c["status"] != "verified"]
        if document["blockers"] != base["blockers"] + [
            "preflight_" + c["name"] + "_" + c["reason"] for c in failures
        ]:
            raise ValueError("Observation blockers changed")
        now = datetime.fromisoformat(observation["observed_at"])
        aware_time(now)
        readers = []
        for name, endpoint in (("source", source), ("target", target)):
            snapshot = observation["inventories"].get(name)
            if snapshot is None:
                readers.append(None)
                continue
            resource = snapshot["resource"]
            proof = DatabaseResourceEvidence(
                **{
                    **resource,
                    "placement": placement(resource["placement"]),
                    "observed_at": datetime.fromisoformat(resource["observed_at"]),
                }
            )
            inventory = DatabaseInventory(
                **{
                    **snapshot,
                    "placement": placement(snapshot["placement"]),
                    "resource": proof,
                    "observed_at": datetime.fromisoformat(snapshot["observed_at"]),
                    "extensions": tuple(tuple(item) for item in snapshot["extensions"]),
                }
            )
            if inventory.placement != endpoint or inventory.plan_id != base["plan_id"]:
                raise ValueError("Inventory binding changed")
            if any(
                not 0 <= (now - at).total_seconds() <= age
                for at in (inventory.observed_at, proof.observed_at)
            ):
                raise ValueError("Expired inventory retained as verified")
            readers.append(SimpleNamespace(inspect=lambda *a, value=inventory, **kw: value))
        if all(reader is not None for reader in readers):
            expected = DatabaseMigrationPreflight(
                *readers,
                clock=lambda: now,
                max_age_seconds=observation["max_age_seconds"],
            ).inspect(source, target, policy, source_revision=base["source_revision"])
            if json.loads(json.dumps(expected)) != document:
                raise ValueError("Report gates or checks changed")
        else:
            if observation["status"] != "blocked" or observation["expires_at"] is not None or not failures:
                raise ValueError("Unknown or incomplete evidence status")
            if document["required_gates"] != base["required_gates"] or set(names) != {
                "source_inventory",
                "target_inventory",
            }:
                raise ValueError("Unverified endpoint cannot advance a gate")
            for name in ("source", "target"):
                verified = next(c["status"] == "verified" for c in checks if c["name"] == name + "_inventory")
                if verified != (name in observation["inventories"]):
                    raise ValueError("Missing verified endpoint")
        return document
    except (KeyError, ValueError, TypeError, AttributeError, OverflowError):
        raise ValueError("Invalid internal migration preflight report") from None
