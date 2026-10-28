"""Exercise bounded collection with real SQL; writes remain transactionally denied."""

from uuid import uuid4

import pytest

from adapters.database.read_benchmark import PostgresReadBenchmark
from application.promotion_performance import validate_window
from tests.contract.test_deployment_reads import setup as setup  # noqa: PLC0414
from tests.unit.test_promotion_performance import SOURCE


def test_real_postgres_read_collection_and_write_denial(setup):
    _, connect, _ = setup
    name = "benchmark_" + uuid4().hex
    with connect() as db:
        db.execute(f"CREATE TABLE {name}(value integer)")
        db.execute(f"INSERT INTO {name} VALUES(42)")
    try:
        observed = []
        result = PostgresReadBenchmark(
            connect, f"SELECT sum(value) FROM {name}", query_id="owned-fixture-v1"
        ).run(
            binding=SOURCE,
            source_revision="a" * 64,
            image_digest=None,
            samples=40,
            concurrency=2,
            pause_seconds=0.5,
            evidence_ref="evidence:contract/readonly",
            observe=observed.append,
        )
        validate_window(result)
        assert result["successes"] == 40 and result["failures"] == 0 and len(observed) == 40
        denied = []
        with pytest.raises(ValueError, match="failed or the measured dataset changed"):
            PostgresReadBenchmark(
                connect, f"DELETE FROM {name} RETURNING value", query_id="deny-write-fixture"
            ).run(
                binding=SOURCE,
                source_revision="a" * 64,
                image_digest=None,
                samples=40,
                concurrency=2,
                pause_seconds=0.5,
                evidence_ref="evidence:contract/denied",
                observe=denied.append,
            )
        assert len(denied) == 40 and not any(x["ok"] for x in denied)
        with connect() as db:
            assert db.execute(f"SELECT value FROM {name}").fetchall() == [(42,)]
    finally:
        with connect() as db:
            db.execute(f"DROP TABLE {name}")
