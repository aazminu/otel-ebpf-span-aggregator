"""CLI entrypoint for `otel_aggregator` diagnostics and invariant self-tests."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from .diagnostics import run_diagnostic_suite, validate_runtime_invariants


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m otel_aggregator",
        description="Run deterministic diagnostics and invariant checks for otel-ebpf-span-aggregator.",
    )
    parser.add_argument("--seed", type=int, default=42, help="Deterministic seed (default: 42)")
    parser.add_argument("--json", action="store_true", help="Emit structured JSON report to stdout")
    parser.add_argument("--self-test", action="store_true", help="Run invariant self-test and exit non-zero on failure")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.self_test:
        report = validate_runtime_invariants(seed=args.seed)
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            status = "PASS" if report["passed"] else "FAIL"
            print(f"[{status}] otel-ebpf-span-aggregator (otel_aggregator) invariants passed={report['passed']} reproducible={report['reproducible']}")
        return 0 if report["passed"] else 1

    suite = run_diagnostic_suite(seed=args.seed)
    if args.json:
        print(json.dumps(suite, indent=2, sort_keys=True))
    else:
        print(f"otel-ebpf-span-aggregator (otel_aggregator) status={suite['status']} metrics={suite['metrics']}")
    return 0 if suite["status"] == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
