"""Explicit operator read benchmark; never runs uploaded SQL or mutates app data.

The trusted factory supplies an audited app-role connection and query. This is
database-path latency, not HTTP latency or a production capacity measurement.
"""

import hashlib
import json
import math
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from ports.promotion_performance import PromotionPerformanceObserver


class PostgresReadBenchmark:
    def __init__(self, connect, query, *, query_id):
        if not callable(connect) or not isinstance(query, str) or not 1 <= len(query) <= 4096:
            raise ValueError("Trusted bounded read query and connector required")
        if not isinstance(query_id, str) or not 1 <= len(query_id) <= 128:
            raise ValueError("Registered query identity required")
        self.connect, self.query = connect, query
        self.workload_sha256 = hashlib.sha256(json.dumps([query_id, query]).encode()).hexdigest()

    def run(
        self,
        *,
        binding,
        source_revision,
        image_digest,
        samples=800,
        concurrency=4,
        pause_seconds=0.05,
        evidence_ref,
        observe=None,
    ):
        if (
            type(samples) is not int
            or not 30 <= samples <= 5000
            or type(concurrency) is not int
            or not 1 <= concurrency <= 16
            or type(pause_seconds) not in (int, float)
            or not math.isfinite(pause_seconds)
            or not 0.01 <= pause_seconds <= 1
            or not 10 <= samples * pause_seconds / concurrency <= 500
        ):
            raise ValueError("Bounded benchmark schedule required")
        started = datetime.now(UTC).isoformat()
        monotonic = time.monotonic()
        barrier = threading.Barrier(concurrency)

        def collect(worker):
            connection = None
            results = []
            barrier.wait(timeout=10)
            try:
                for _ in range(worker, samples, concurrency):
                    begin = time.monotonic()
                    if begin - monotonic > 590:
                        results.append({"ok": False, "ms": 0})
                        continue
                    try:
                        if connection is None or connection.closed:
                            connection = self.connect()
                        with connection.transaction():
                            connection.execute("SET TRANSACTION READ ONLY")
                            connection.execute("SET LOCAL statement_timeout='2s'")
                            rows = connection.execute(self.query).fetchmany(101)
                            if len(rows) > 100:
                                raise ValueError("Benchmark output exceeds registered bound")
                            digest = hashlib.sha256(json.dumps(rows, default=str).encode()).hexdigest()
                        sample = {
                            "ok": True,
                            "ms": (time.monotonic() - begin) * 1000,
                            "dataset_sha256": digest,
                        }
                    except Exception:  # noqa: BLE001 -- count failures; never expose SQL/credentials or retry a sample
                        if connection is not None:
                            connection.close()
                        connection = None
                        sample = {"ok": False, "ms": (time.monotonic() - begin) * 1000}
                    results.append(sample)
                    if observe is not None:
                        observe({"worker": worker, **sample})
                    time.sleep(pause_seconds)
            finally:
                if connection is not None:
                    connection.close()
            return results

        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            results = [item for group in executor.map(collect, range(concurrency)) for item in group]
        duration = time.monotonic() - monotonic
        finished = datetime.now(UTC).isoformat()
        success = sorted(x["ms"] for x in results if x["ok"])
        datasets = {x["dataset_sha256"] for x in results if x["ok"]}
        if not success or len(datasets) != 1:
            raise ValueError("Read benchmark failed or the measured dataset changed; retain raw evidence")
        return {
            "schema_version": 1,
            "binding": binding,
            "source_revision": source_revision,
            "image_digest": image_digest,
            "workload_sha256": self.workload_sha256,
            "dataset_sha256": datasets.pop(),
            "concurrency": concurrency,
            "samples": len(results),
            "successes": len(success),
            "failures": len(results) - len(success),
            "duration_seconds": duration,
            "p50_ms": success[math.ceil(len(success) * 0.5) - 1],
            "p95_ms": success[math.ceil(len(success) * 0.95) - 1],
            "throughput_rps": len(success) / duration,
            "started_at": started,
            "finished_at": finished,
            "evidence_ref": evidence_ref,
            "scope": "postgresql_application_read",
        }


class RegisteredPostgresPromotionBenchmark(PromotionPerformanceObserver):
    """A trusted worker factory pins two connectors, SQL and an evidence sink.

    No HTTP or queue payload can configure these capabilities. Evidence must be
    durably retained before a summary can be attached to the deployment record.
    """

    def __init__(
        self,
        plan,
        source_connect,
        target_connect,
        query,
        *,
        query_id,
        evidence_prefix,
        evidence_sink,
        samples=800,
        concurrency=4,
        pause_seconds=0.075,
    ):
        import re
        from copy import deepcopy

        if (
            not callable(evidence_sink)
            or not isinstance(evidence_prefix, str)
            or not re.fullmatch(r"evidence:[A-Za-z0-9/_-]{1,160}", evidence_prefix)
        ):
            raise ValueError("Registered durable benchmark evidence sink required")
        self.plan = deepcopy(plan)
        self.collectors = [
            PostgresReadBenchmark(connect, query, query_id=query_id)
            for connect in (source_connect, target_connect)
        ]
        self.prefix, self.sink = evidence_prefix, evidence_sink
        self.samples, self.concurrency, self.pause = samples, concurrency, pause_seconds

    def measure(self, plan, binding, *, guard):
        from copy import deepcopy

        from application.promotion_performance import validate_window

        guard()
        if plan != self.plan or binding not in (plan["source"], plan["target"]):
            raise ValueError("Exact registered benchmark plan and binding required")
        index = 0 if binding == plan["source"] else 1
        reference = self.prefix + ("/before" if index == 0 else "/after")
        raw = []
        window = self.collectors[index].run(
            binding=deepcopy(binding),
            source_revision=plan["source_revision"],
            image_digest=None,
            samples=self.samples,
            concurrency=self.concurrency,
            pause_seconds=self.pause,
            evidence_ref=reference,
            observe=raw.append,
        )
        guard()
        validate_window(window)
        if self.sink(reference, deepcopy(window), raw) != reference:
            raise ValueError("Benchmark evidence was not durably retained at its registered reference")
        guard()
        return window
