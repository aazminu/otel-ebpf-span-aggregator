# `otel-ebpf-span-aggregator`

**High-Throughput OpenTelemetry Distributed Trace Collector, Tail-Based Sampling Engine, DDSketch Relative-Error Quantile Aggregator, and Linux `cgroup v2` Container Telemetry Correlator**

[![CI](https://github.com/aazminu/otel-ebpf-span-aggregator/actions/workflows/ci.yml/badge.svg)](https://github.com/aazminu/otel-ebpf-span-aggregator/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

Designed and authored by **Abdullah Azmi** ([abdullahazmi.com](https://abdullahazmi.com) · [@aazminu](https://github.com/aazminu)).

---

## 1. Systems Architecture & Motivation

In large-scale cloud observability pipelines, naive head-based trace sampling (`1%` random decision at the ingress proxy) discards `99%` of downstream execution exceptions, tail-latency regressions, and container OOM-kill cascades—while simultaneously skewing service RED metrics (*Rate, Errors, Duration*) if metrics are computed post-sampling.

`otel-ebpf-span-aggregator` implements the core data-plane primitives of a production APM trace agent:

1. **Pre-Sampling DDSketch Metric Extraction (`ddsketch.py`)**: Every ingested span updates per-service **DDSketch** logarithmic histograms *before* any sampling decision is made, guaranteeing `100%` un-biased count, error rate, and $\alpha$-accurate $p50 / p95 / p99$ latency distributions across arbitrarily many collector shards.
2. **Trace-Aware Tail-Based Ring Buffer (`tail_sampler.py`)**: Assembles out-of-order spans into in-flight Directed Acyclic Graphs (`TraceDAG`) keyed by `trace_id`, computes end-to-end critical path latency, detects orphan spans, and executes a multi-tier retention policy.
3. **Linux `cgroup v2` / eBPF Resource Pressure Correlator (`cgroup_correlator.py`)**: Parses kernel `/sys/fs/cgroup` telemetry (`cpu.stat`, `memory.pressure` PSI stalls, `memory.events`, and `exitCode=137` `SIGKILL` events) over sliding windows to attribute span latency spikes to **CPU CFS quota throttling**, **memory reclaim thrashing**, or **container OOM kills**.

```
                          ┌───────────────────────────────────────────────┐
  OTLP Span Stream ──────►│ 1. Pre-Sampling DDSketch Histogram Aggregator │
                          │    k(x) = ceil(log_gamma(x)),  |q^ - q| <= αq │
                          └──────────────────────┬────────────────────────┘
                                                 │
                                                 ▼
┌────────────────────────────────────┐   ┌────────────────────────────────┐
│ Linux cgroup v2 / eBPF Snapshots   │──►│ 2. Container Pressure Enricher │
│  • cpu.stat (nr_throttled)         │   │    • CPU_CFS_THROTTLED         │
│  • memory.pressure (PSI some/full) │   │    • MEMORY_PSI_STALL          │
│  • memory.events (oom_kill / 137)  │   │    • OOM_KILLED (exitCode=137) │
└────────────────────────────────────┘   └───────────────┬────────────────┘
                                                         │
                                                         ▼
                                         ┌────────────────────────────────┐
                                         │ 3. TraceDAG Ring Buffer (LRU)  │
                                         │    • Error Span Propagation    │
                                         │    • Dynamic DDSketch p99 SLA  │
                                         │    • Consistent FNV-1a Hash    │
                                         └────────────────────────────────┘
```

---

## 2. DDSketch Logarithmic Bucket Mathematics

Following Masson, Rim, and Lee (*VLDB 2019*), given a target relative error $\alpha \in (0, 1)$, we define the logarithmic base $\gamma$:

$$\gamma = \frac{1 + \alpha}{1 - \alpha}$$

Every positive span duration $x > x_{\min}$ is mapped in $O(1)$ time to integer bucket index $k(x)$:

$$k(x) = \left\lceil \log_{\gamma}(x) \right\rceil = \left\lceil \frac{\ln(x)}{\ln(\gamma)} \right\rceil$$

When querying any quantile $q \in [0, 1]$, the bucket at target rank $r = \lfloor q(N - 1) \rfloor$ with index $k$ reconstructs its representative latency value via the harmonic midpoint:

$$\hat{x}(k) = \frac{2 \cdot \gamma^k}{\gamma + 1}$$

Because $\gamma^{k-1} < x \le \gamma^k$ and $\frac{\gamma - 1}{\gamma + 1} = \alpha$, every quantile estimate $\hat{q}$ satisfies the strict relative-error invariant:

$$\left| \hat{q} - q_{\text{true}} \right| \le \alpha \cdot q_{\text{true}}$$

When the number of active buckets in a `DenseStore` exceeds `max_bins` (default `2048`), the lowest-indexed buckets are collapsed into the adjacent bucket (`_collapse_if_needed`), bounding memory overhead per service shard while preserving exact tail accuracy ($p95, p99, p99.9$).

---

## 3. Tail-Based Sampling Decision Tree

When a trace completes or is evicted at the ring-buffer high-water mark (`max_in_flight_traces`), `TailSamplingEngine._evaluate_dag` evaluates the assembled `TraceDAG` in strict priority order:

| Priority | Policy Rule | Condition | Retention Rate |
| :--- | :--- | :--- | :--- |
| **P1** | `ERROR_SPAN` | Any span in `TraceDAG` has `status == ERROR`, `http_status >= 500`, or `error=true` | **100%** |
| **P2** | `CONTAINER_PRESSURE` | Any span enriched with `cgroup.throttled`, `cgroup.psi_stall`, or `cgroup.oom_kill` (`exitCode=137`) | **100%** |
| **P3** | `LATENCY_OUTLIER_STATIC` | Root / end-to-end trace duration $\ge$ `static_latency_threshold_ms` | **100%** |
| **P4** | `LATENCY_OUTLIER_P99` | Any span duration $\ge 1.05 \times \text{DDSketch}_{p99}(\text{service})$ | **100%** |
| **P5** | `BASELINE_HASH_SAMPLED` | $\text{FNV1a}_{64}(\text{trace\_id}) / 2^{64} < \text{baseline\_sample\_rate}$ | `baseline_sample_rate` |

Because **P5** hashes the `trace_id` using deterministic 64-bit FNV-1a (`0xCBF29CE484222325`), stateless or sharded collector replicas independently arrive at the exact same baseline sampling decision without cross-node RPCs.

---

## 4. Linux `cgroup v2` Container Telemetry Correlation

Application latency spikes frequently originate from container scheduler starvation rather than application code bottlenecks. `CgroupSpanCorrelator` ingests paired snapshots of `/sys/fs/cgroup/<pod>/` across `[t_0, t_1]`:

- **CPU CFS Quota Throttling (`cpu.stat`)**: Computes $\Delta \text{nr\_throttled} / \Delta \text{nr\_periods}$ and $\Delta \text{throttled\_usec}$. If the throttle ratio exceeds `throttle_ratio_threshold` (default `15%`), overlapping spans are attributed to `RootCauseCategory.CPU_CFS_THROTTLED`.
- **Linux PSI Memory Thrashing (`memory.pressure`)**: Parses `some` and `full` stall lines (`avg10`, `avg60`, `avg300`, `total`). When $\Delta \text{full\_total\_usec} \ge 10\text{ ms}$ during a span window, all threads in the container were stalled on kernel page reclaim, attributing the span to `RootCauseCategory.MEMORY_PSI_STALL`.
- **OOM Kill / `SIGKILL` (`memory.events` & `exitCode=137`)**: Correlates $\Delta \text{oom\_kill} > 0$ or container termination status `137` (`128 + SIGKILL(9)`) to `RootCauseCategory.OOM_KILLED`, tagging the span with `container.exit_code=137` and forcing `100%` tail-sampler retention.

---

## 5. Quickstart & Verification

```bash
pip install -e ".[dev]"
pytest -v
```

### Example Usage

```python
from otel_aggregator import (
    DDSketch,
    Span,
    SpanStatus,
    TailSamplingConfig,
    TailSamplingEngine,
)

engine = TailSamplingEngine(TailSamplingConfig(baseline_sample_rate=0.05))

engine.ingest_span(
    Span(
        trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
        span_id="00f067aa0ba902b7",
        parent_span_id=None,
        service_name="edge-gateway",
        operation_name="POST /v1/checkout",
        start_time_ns=1_700_000_000_000,
        end_time_ns=1_700_045_000_000,
        status=SpanStatus.OK,
    )
)
engine.ingest_span(
    Span(
        trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
        span_id="b9c7c989f97918e1",
        parent_span_id="00f067aa0ba902b7",
        service_name="ledger-writer",
        operation_name="INSERT ledger_entry",
        start_time_ns=1_700_010_000_000,
        end_time_ns=1_700_040_000_000,
        status=SpanStatus.ERROR,
        http_status_code=503,
    )
)

decision = engine.evaluate_and_flush("4bf92f3577b34da6a3ce929d0e0e4736")
assert decision.sampled is True
assert decision.reason.value == "ERROR_SPAN"
```

---

## License

MIT License © 2026 Abdullah Azmi.


## CLI Diagnostics & Invariant Verification

Run the built-in deterministic diagnostic probe and invariant self-check directly via the module CLI:

```bash
PYTHONPATH=src python -m otel_aggregator --self-test --json
```

Run the complete regression test suite:

```bash
PYTHONPATH=src pytest -q
```
