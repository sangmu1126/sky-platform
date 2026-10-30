"""Measure deterministic detector replay. Does not perform a live red team."""

import argparse
import hashlib
import json
from pathlib import Path

from application.security_detector_evaluation import evaluate_secret_detector


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=20)
    args = parser.parse_args()
    report = evaluate_secret_detector(repetitions=args.repetitions)
    report["implementation_sha256"] = hashlib.sha256(
        (Path(__file__).resolve().parents[1] / "src/adapters/aws/security_monitor.py").read_bytes()
    ).hexdigest()
    with args.output.open("x") as stream:
        json.dump(report, stream, indent=2)
    print(json.dumps({"passed": report["passed"], "totals": report["totals"], "live_cloud_calls": False}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
