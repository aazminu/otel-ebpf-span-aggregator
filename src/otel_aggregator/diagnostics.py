"""Deterministic runtime diagnostics and invariant verification for `otel_aggregator`."""

from __future__ import annotations

import time
from typing import Any

from .ddsketch import DDSketch
from .tail_sampler import fnv1a_64

def _domain_probe(seed: int) -> dict:
    sketch = DDSketch(0.01)
    for v in range(1, 201):
        sketch.add(float(v))
    p50 = sketch.quantile(0.50)
    p99 = sketch.quantile(0.99)
    h = fnv1a_64("trace-0001")
    return {
        "count": sketch.count,
        "p50": round(p50, 2),
        "p99": round(p99, 2),
        "trace_hash": h,
        "invariants_ok": (sketch.count == 200 and 95.0 <= p50 <= 105.0 and 194.0 <= p99 <= 202.0 and h > 0),
    }


def run_diagnostic_suite(seed: int = 42) -> dict[str, Any]:
    """Execute deterministic domain probe for `otel-ebpf-span-aggregator` and return structured metrics."""
    if not isinstance(seed, int) or seed < 0:
        raise ValueError("seed must be a non-negative integer")
    t0 = time.perf_counter()
    metrics = _domain_probe(seed)
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
    return {
        "repository": "otel-ebpf-span-aggregator",
        "package": "otel_aggregator",
        "seed": seed,
        "elapsed_ms": elapsed_ms,
        "metrics": metrics,
        "status": "ok" if metrics.get("invariants_ok", False) else "failed",
    }


def validate_runtime_invariants(seed: int = 42) -> dict[str, Any]:
    """Validate deterministic reproducibility and domain invariants for `otel_aggregator`."""
    run_a = run_diagnostic_suite(seed=seed)
    run_b = run_diagnostic_suite(seed=seed)
    reproducible = run_a["metrics"] == run_b["metrics"]
    passed = bool(run_a["metrics"].get("invariants_ok", False)) and reproducible
    return {
        "repository": "otel-ebpf-span-aggregator",
        "package": "otel_aggregator",
        "seed": seed,
        "reproducible": reproducible,
        "passed": passed,
        "metrics": run_a["metrics"],
    }
