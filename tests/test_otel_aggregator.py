"""
Comprehensive test suite for `otel-ebpf-span-aggregator`:
- DDSketch logarithmic indexing, alpha-relative error bounds, negative/zero handling,
  dense store bucket collapsing, and associative/commutative shard merging.
- TraceDAG reconstruction, orphan span detection, and critical path latency calculation.
- TailSamplingEngine multi-criteria retention (error propagation, cgroup pressure,
  static SLA outlier, dynamic DDSketch p99 outlier, deterministic FNV-1a hash sampling,
  and ring-buffer watermark eviction).
- CgroupSpanCorrelator parsing of Linux cgroup v2 `cpu.stat`, `memory.pressure` (PSI),
  `memory.events`, and root-cause attribution (`CPU_CFS_THROTTLED`, `MEMORY_PSI_STALL`,
  `OOM_KILLED` / `exitCode=137`).
"""

from __future__ import annotations

import math
import random
import pytest

from otel_aggregator import (
    ContainerCgroupSnapshot,
    CgroupSpanCorrelator,
    DDSketch,
    RootCauseCategory,
    SamplingReason,
    Span,
    SpanStatus,
    TailSamplingConfig,
    TailSamplingEngine,
    TraceDAG,
    fnv1a_64,
    parse_cpu_stat,
    parse_memory_events,
    parse_memory_pressure,
)


# ============================================================================
# 1. DDSketch Relative-Error & Merge Guarantees (Tests 1 - 7)
# ============================================================================


def test_ddsketch_relative_error_bound_across_orders_of_magnitude() -> None:
    """Verify |q_hat - q_true| <= alpha * q_true across 4 orders of magnitude."""
    alpha = 0.01
    sketch = DDSketch(relative_accuracy=alpha)
    rng = random.Random(42)
    samples = [rng.expovariate(1.0 / 50.0) + 0.1 for _ in range(5000)]
    sketch.add_batch(samples)

    sorted_samples = sorted(samples)
    for q in (0.10, 0.25, 0.50, 0.75, 0.90, 0.95, 0.99):
        true_val = sorted_samples[int(q * (len(sorted_samples) - 1))]
        est_val = sketch.quantile(q)
        assert est_val is not None
        rel_err = abs(est_val - true_val) / true_val
        assert rel_err <= alpha, f"Quantile {q} exceeded alpha={alpha}: rel_err={rel_err:.5f}"


def test_ddsketch_associative_and_commutative_shard_merging() -> None:
    """Verify merging distributed collector shards yields identical quantiles."""
    alpha = 0.01
    s1 = DDSketch(relative_accuracy=alpha)
    s2 = DDSketch(relative_accuracy=alpha)
    s3 = DDSketch(relative_accuracy=alpha)
    monolithic = DDSketch(relative_accuracy=alpha)

    data1 = [float(i) for i in range(1, 300)]
    data2 = [float(i * 2.5) for i in range(1, 300)]
    data3 = [float(i * 10.0) for i in range(1, 300)]

    s1.add_batch(data1)
    s2.add_batch(data2)
    s3.add_batch(data3)
    monolithic.add_batch(data1 + data2 + data3)

    # Merge (s1 + s2) + s3
    left = DDSketch(relative_accuracy=alpha)
    left.merge(s1)
    left.merge(s2)
    left.merge(s3)

    # Merge s3 + (s2 + s1)
    right = DDSketch(relative_accuracy=alpha)
    right.merge(s3)
    right.merge(s2)
    right.merge(s1)

    assert left.count == monolithic.count == 897
    assert math.isclose(left.sum, monolithic.sum, rel_tol=1e-9)
    assert math.isclose(left.p50 or 0.0, monolithic.p50 or 0.0, rel_tol=1e-12)
    assert math.isclose(left.p99 or 0.0, right.p99 or 0.0, rel_tol=1e-12)


def test_ddsketch_zero_and_negative_values() -> None:
    """Verify DDSketch accurately tracks negative clock-skew deltas, zeros, and positives."""
    sketch = DDSketch(relative_accuracy=0.02)
    for v in [-100.0, -50.0, -10.0, 0.0, 0.0, 10.0, 50.0, 100.0, 500.0]:
        sketch.add(v)

    assert sketch.count == 9
    assert sketch.zero_count == 2
    assert sketch.min_value == -100.0
    assert sketch.max_value == 500.0
    assert sketch.quantile(0.0) == -100.0
    assert sketch.quantile(1.0) == 500.0
    # Median of 9 elements is index 4 -> 0.0
    assert sketch.p50 == 0.0


def test_ddsketch_max_bins_collapsing_preserves_tail_quantiles() -> None:
    """Verify DenseStore collapses lowest buckets when max_bins is exceeded without corrupting p99."""
    sketch = DDSketch(relative_accuracy=0.005, max_bins=16)
    values = [float(2**i) for i in range(1, 40)]
    sketch.add_batch(values)

    assert len(sketch.positive_store.bins) <= 16
    assert sketch.positive_store.total_count == len(values)
    p99 = sketch.p99
    assert p99 is not None
    true_p99 = values[int(0.99 * (len(values) - 1))]
    assert abs(p99 - true_p99) / true_p99 <= 0.005


def test_ddsketch_invalid_parameters_and_inputs() -> None:
    """Verify validation errors on out-of-range alpha, NaN/Inf observations, or mismatched merges."""
    with pytest.raises(ValueError):
        DDSketch(relative_accuracy=0.0)
    with pytest.raises(ValueError):
        DDSketch(relative_accuracy=1.0)

    s = DDSketch(relative_accuracy=0.01)
    with pytest.raises(ValueError):
        s.add( float("nan") )
    with pytest.raises(ValueError):
        s.add( float("inf") )
    with pytest.raises(ValueError):
        s.quantile(1.5)

    other = DDSketch(relative_accuracy=0.05)
    with pytest.raises(ValueError):
        s.merge(other)


def test_ddsketch_empty_sketch_behavior() -> None:
    """Verify empty sketch returns None for quantiles and 0.0 for count/avg."""
    sketch = DDSketch()
    assert sketch.count == 0
    assert sketch.avg == 0.0
    assert sketch.min_value is None
    assert sketch.max_value is None
    assert sketch.p50 is None
    assert sketch.p95 is None
    assert sketch.p99 is None


def test_ddsketch_weighted_insertions() -> None:
    """Verify weighted insertions match repeated individual insertions."""
    s_weighted = DDSketch(relative_accuracy=0.01)
    s_single = DDSketch(relative_accuracy=0.01)

    s_weighted.add(25.0, weight=50)
    s_weighted.add(250.0, weight=5)

    for _ in range(50):
        s_single.add(25.0)
    for _ in range(5):
        s_single.add(250.0)

    assert s_weighted.count == s_single.count == 55
    assert math.isclose(s_weighted.p95 or 0.0, s_single.p95 or 0.0, rel_tol=1e-12)


# ============================================================================
# 2. TraceDAG Reconstruction & Critical Path Analysis (Tests 8 - 10)
# ============================================================================


def test_trace_dag_reconstruction_and_orphan_detection() -> None:
    """Verify TraceDAG identifies root span, children adjacency, and missing-parent orphans."""
    dag = TraceDAG("trace-abc-123")
    root = Span(
        trace_id="trace-abc-123",
        span_id="span-root",
        parent_span_id=None,
        service_name="api-gateway",
        operation_name="GET /checkout",
        start_time_ns=1_000_000_000,
        end_time_ns=1_120_000_000,
    )
    child = Span(
        trace_id="trace-abc-123",
        span_id="span-child",
        parent_span_id="span-root",
        service_name="payment-svc",
        operation_name="AuthorizeCard",
        start_time_ns=1_010_000_000,
        end_time_ns=1_090_000_000,
    )
    orphan = Span(
        trace_id="trace-abc-123",
        span_id="span-orphan",
        parent_span_id="missing-middle-span",
        service_name="ledger-db",
        operation_name="INSERT ledger",
        start_time_ns=1_020_000_000,
        end_time_ns=1_050_000_000,
    )

    dag.add_span(root)
    dag.add_span(child)
    dag.add_span(orphan)

    assert dag.span_count == 3
    assert dag.root_span == root
    assert dag.orphan_span_ids == ["span-orphan"]
    assert math.isclose(dag.trace_duration_ms, 120.0)
    assert math.isclose(dag.critical_path_ms(), 120.0)


def test_trace_dag_rejects_mismatched_trace_id() -> None:
    """Verify adding a span from another trace raises ValueError."""
    dag = TraceDAG("trace-1")
    wrong_span = Span(
        trace_id="trace-2",
        span_id="s1",
        parent_span_id=None,
        service_name="auth",
        operation_name="verify",
        start_time_ns=0,
        end_time_ns=1_000_000,
    )
    with pytest.raises(ValueError):
        dag.add_span(wrong_span)


def test_fnv1a_64_deterministic_consistency() -> None:
    """Verify FNV-1a 64-bit hash produces known test vectors and deterministic scores."""
    # Standard FNV-1a 64-bit test vector for empty string is offset basis
    assert fnv1a_64("") == 0xCBF29CE484222325
    # Verify stability across calls
    assert fnv1a_64("4bf92f3577b34da6a3ce929d0e0e4736") == fnv1a_64(
        "4bf92f3577b34da6a3ce929d0e0e4736"
    )


# ============================================================================
# 3. Tail-Based Sampling Decision Engine (Tests 11 - 15)
# ============================================================================


def test_tail_sampler_retains_leaf_error_propagated_to_trace() -> None:
    """Verify a 503 error on a deep leaf span forces 100% retention of the entire trace."""
    cfg = TailSamplingConfig(baseline_sample_rate=0.0, static_latency_threshold_ms=10_000.0)
    engine = TailSamplingEngine(cfg)

    engine.ingest_span(
        Span(
            trace_id="trace-err-1",
            span_id="root",
            parent_span_id=None,
            service_name="edge-proxy",
            operation_name="POST /orders",
            start_time_ns=0,
            end_time_ns=25_000_000,  # 25 ms
            status=SpanStatus.OK,
        )
    )
    engine.ingest_span(
        Span(
            trace_id="trace-err-1",
            span_id="leaf-db",
            parent_span_id="root",
            service_name="postgres-shard-04",
            operation_name="COMMIT",
            start_time_ns=5_000_000,
            end_time_ns=20_000_000,
            status=SpanStatus.ERROR,
            http_status_code=503,
        )
    )

    decision = engine.evaluate_and_flush("trace-err-1")
    assert decision.sampled is True
    assert decision.reason == SamplingReason.ERROR_SPAN
    assert decision.error_services == ("postgres-shard-04",)


def test_tail_sampler_retains_static_and_dynamic_p99_latency_outliers() -> None:
    """Verify both static SLA breach and dynamic DDSketch p99 outlier trigger trace retention."""
    cfg = TailSamplingConfig(
        baseline_sample_rate=0.0,
        static_latency_threshold_ms=1000.0,
        enable_dynamic_p99_outlier=True,
        min_samples_for_dynamic_p99=25,
        dynamic_p99_multiplier=1.05,
    )
    engine = TailSamplingEngine(cfg)

    # Warm up service DDSketch with 30 normal fast traces (10-15ms)
    for i in range(30):
        tid = f"trace-fast-{i}"
        engine.ingest_span(
            Span(
                trace_id=tid,
                span_id=f"s-{i}",
                parent_span_id=None,
                service_name="search-index",
                operation_name="QueryShard",
                start_time_ns=0,
                end_time_ns=12_000_000,  # 12 ms
            )
        )
        d = engine.evaluate_and_flush(tid)
        assert d.sampled is False
        assert d.reason == SamplingReason.DROPPED_BASELINE

    # Now send a trace with 180ms latency (< 1000ms static SLA, but >10x service p99!)
    engine.ingest_span(
        Span(
            trace_id="trace-p99-spike",
            span_id="s-spike",
            parent_span_id=None,
            service_name="search-index",
            operation_name="QueryShard",
            start_time_ns=0,
            end_time_ns=180_000_000,  # 180 ms
        )
    )
    spike_decision = engine.evaluate_and_flush("trace-p99-spike")
    assert spike_decision.sampled is True
    assert spike_decision.reason == SamplingReason.LATENCY_OUTLIER_P99


def test_tail_sampler_ring_buffer_watermark_eviction() -> None:
    """Verify exceeding max_in_flight_traces evicts and evaluates the oldest trace LRU-first."""
    cfg = TailSamplingConfig(max_in_flight_traces=3, baseline_sample_rate=0.0)
    engine = TailSamplingEngine(cfg)

    for i in range(3):
        evicted = engine.ingest_span(
            Span(
                trace_id=f"t-{i}",
                span_id=f"s-{i}",
                parent_span_id=None,
                service_name="svc",
                operation_name="op",
                start_time_ns=0,
                end_time_ns=5_000_000,
                status=SpanStatus.ERROR if i == 0 else SpanStatus.OK,
            )
        )
        assert evicted is None

    # Ingesting a 4th distinct trace_id must evict t-0 (which had an error)
    evicted_decision = engine.ingest_span(
        Span(
            trace_id="t-3",
            span_id="s-3",
            parent_span_id=None,
            service_name="svc",
            operation_name="op",
            start_time_ns=0,
            end_time_ns=5_000_000,
        )
    )
    assert evicted_decision is not None
    assert evicted_decision.trace_id == "t-0"
    assert evicted_decision.sampled is True
    assert evicted_decision.reason == SamplingReason.ERROR_SPAN


def test_tail_sampler_consistent_hash_rate_accuracy() -> None:
    """Verify baseline FNV-1a sampling rate converges close to configured 20% target."""
    cfg = TailSamplingConfig(
        baseline_sample_rate=0.20,
        static_latency_threshold_ms=999_999.0,
        enable_dynamic_p99_outlier=False,
    )
    engine = TailSamplingEngine(cfg)

    sampled_count = 0
    total_traces = 500
    for i in range(total_traces):
        tid = f"trace-consistent-{i:05d}"
        engine.ingest_span(
            Span(
                trace_id=tid,
                span_id="root",
                parent_span_id=None,
                service_name="web",
                operation_name="GET /",
                start_time_ns=0,
                end_time_ns=5_000_000,
            )
        )
        if engine.evaluate_and_flush(tid).sampled:
            sampled_count += 1

    observed_rate = sampled_count / float(total_traces)
    assert 0.14 <= observed_rate <= 0.26


# ============================================================================
# 4. Linux cgroup v2 & eBPF Container Telemetry Correlator (Tests 16 - 20)
# ============================================================================


def test_cgroup_v2_parsers_cpu_stat_psi_and_memory_events() -> None:
    """Verify parsing of kernel `/sys/fs/cgroup` cpu.stat, memory.pressure, and memory.events."""
    raw_cpu = """
    usage_usec 48291000
    user_usec 31000000
    system_usec 17291000
    nr_periods 400
    nr_throttled 120
    throttled_usec 950000
    """
    cpu = parse_cpu_stat(raw_cpu)
    assert cpu.nr_periods == 400
    assert cpu.nr_throttled == 120
    assert cpu.throttled_usec == 950000

    raw_psi = """
    some avg10=14.20 avg60=5.10 avg300=1.05 total=890000
    full avg10=6.50 avg60=2.00 avg300=0.40 total=310000
    """
    psi = parse_memory_pressure(raw_psi)
    assert math.isclose(psi.some.avg10, 14.20)
    assert psi.some.total_usec == 890000
    assert math.isclose(psi.full.avg10, 6.50)
    assert psi.full.total_usec == 310000

    raw_events = """
    low 0
    high 42
    max 7
    oom 2
    oom_kill 1
    """
    ev = parse_memory_events(raw_events)
    assert ev.high == 42
    assert ev.oom == 2
    assert ev.oom_kill == 1


def test_cgroup_correlator_attributes_cpu_cfs_throttling() -> None:
    """Verify spans overlapping heavy CFS quota throttling are classified as CPU_CFS_THROTTLED."""
    correlator = CgroupSpanCorrelator(throttle_ratio_threshold=0.20)
    snap_t0 = ContainerCgroupSnapshot(
        container_id="container-checkout-01",
        timestamp_ns=1_000_000_000,
        cpu_stat=parse_cpu_stat("nr_periods 100\nnr_throttled 10\nthrottled_usec 50000"),
        memory_pressure=parse_memory_pressure("some total=1000\nfull total=0"),
        memory_events=parse_memory_events("oom_kill 0"),
    )
    snap_t1 = ContainerCgroupSnapshot(
        container_id="container-checkout-01",
        timestamp_ns=2_000_000_000,
        cpu_stat=parse_cpu_stat("nr_periods 150\nnr_throttled 35\nthrottled_usec 410000"),
        memory_pressure=parse_memory_pressure("some total=1200\nfull total=0"),
        memory_events=parse_memory_events("oom_kill 0"),
    )
    correlator.record_snapshot_pair(snap_t0, snap_t1)

    span = Span(
        trace_id="trace-cpu-throttle",
        span_id="span-1",
        parent_span_id=None,
        service_name="checkout-svc",
        operation_name="ComputePricing",
        start_time_ns=1_100_000_000,
        end_time_ns=1_600_000_000,
        container_id="container-checkout-01",
    )

    report = correlator.correlate_span(span)
    assert report.root_cause == RootCauseCategory.CPU_CFS_THROTTLED
    assert math.isclose(report.throttle_ratio, 0.50)  # (35 - 10) / (150 - 100) = 25/50
    assert math.isclose(report.throttled_ms, 360.0)
    assert report.enriched_span.has_container_anomaly is True


def test_cgroup_correlator_attributes_memory_psi_stall() -> None:
    """Verify spans overlapping high PSI full memory thrashing are classified as MEMORY_PSI_STALL."""
    correlator = CgroupSpanCorrelator(psi_full_stall_threshold_ms=15.0)
    snap_t0 = ContainerCgroupSnapshot(
        container_id="container-jvm-02",
        timestamp_ns=10_000_000_000,
        cpu_stat=parse_cpu_stat("nr_periods 100\nnr_throttled 1\nthrottled_usec 1000"),
        memory_pressure=parse_memory_pressure("some total=50000\nfull total=10000"),
        memory_events=parse_memory_events("high 5\noom_kill 0"),
    )
    snap_t1 = ContainerCgroupSnapshot(
        container_id="container-jvm-02",
        timestamp_ns=11_000_000_000,
        cpu_stat=parse_cpu_stat("nr_periods 120\nnr_throttled 1\nthrottled_usec 1000"),
        memory_pressure=parse_memory_pressure("some total=140000\nfull total=65000"),  # +55ms full stall
        memory_events=parse_memory_events("high 28\noom_kill 0"),
    )
    correlator.record_snapshot_pair(snap_t0, snap_t1)

    span = Span(
        trace_id="trace-psi",
        span_id="span-jvm",
        parent_span_id=None,
        service_name="catalog-jvm",
        operation_name="LoadProductGraph",
        start_time_ns=10_200_000_000,
        end_time_ns=10_400_000_000,
        container_id="container-jvm-02",
    )

    report = correlator.correlate_span(span)
    assert report.root_cause == RootCauseCategory.MEMORY_PSI_STALL
    assert math.isclose(report.psi_full_stall_ms, 55.0)
    assert report.enriched_span.attributes["cgroup.psi_stall"] == "true"


def test_cgroup_correlator_detects_oom_kill_exit_137_and_forces_tail_retention() -> None:
    """Verify container exitCode=137 / oom_kill enriches the span and forces tail sampler retention."""
    correlator = CgroupSpanCorrelator()
    snap_t0 = ContainerCgroupSnapshot(
        container_id="container-worker-99",
        timestamp_ns=5_000_000_000,
        cpu_stat=parse_cpu_stat("nr_periods 50\nnr_throttled 0"),
        memory_pressure=parse_memory_pressure("some total=0\nfull total=0"),
        memory_events=parse_memory_events("oom_kill 0"),
    )
    snap_t1 = ContainerCgroupSnapshot(
        container_id="container-worker-99",
        timestamp_ns=6_000_000_000,
        cpu_stat=parse_cpu_stat("nr_periods 60\nnr_throttled 0"),
        memory_pressure=parse_memory_pressure("some total=20000\nfull total=15000"),
        memory_events=parse_memory_events("oom_kill 1"),
        last_exit_code=137,
    )
    correlator.record_snapshot_pair(snap_t0, snap_t1)

    raw_span = Span(
        trace_id="trace-oom-137",
        span_id="span-oom",
        parent_span_id=None,
        service_name="embedding-worker",
        operation_name="BatchEncode",
        start_time_ns=5_100_000_000,
        end_time_ns=5_110_000_000,  # Only 10ms before SIGKILL
        status=SpanStatus.OK,
        container_id="container-worker-99",
    )

    report = correlator.correlate_span(raw_span)
    assert report.root_cause == RootCauseCategory.OOM_KILLED
    assert report.oom_killed is True
    assert report.severity_score == 1.0
    assert report.enriched_span.attributes["container.exit_code"] == "137"

    # Feed enriched span into TailSamplingEngine with 0% baseline rate
    sampler = TailSamplingEngine(TailSamplingConfig(baseline_sample_rate=0.0))
    sampler.ingest_span(report.enriched_span)
    decision = sampler.evaluate_and_flush("trace-oom-137")
    assert decision.sampled is True
    assert decision.reason == SamplingReason.CONTAINER_PRESSURE


def test_cgroup_correlator_application_bound_when_no_pressure() -> None:
    """Verify healthy container metrics classify slow spans as APPLICATION_BOUND."""
    correlator = CgroupSpanCorrelator()
    snap_t0 = ContainerCgroupSnapshot(
        container_id="container-healthy",
        timestamp_ns=1_000_000_000,
        cpu_stat=parse_cpu_stat("nr_periods 100\nnr_throttled 0\nthrottled_usec 0"),
        memory_pressure=parse_memory_pressure("some total=0\nfull total=0"),
        memory_events=parse_memory_events("oom_kill 0"),
    )
    snap_t1 = ContainerCgroupSnapshot(
        container_id="container-healthy",
        timestamp_ns=2_000_000_000,
        cpu_stat=parse_cpu_stat("nr_periods 200\nnr_throttled 1\nthrottled_usec 500"),
        memory_pressure=parse_memory_pressure("some total=100\nfull total=0"),
        memory_events=parse_memory_events("oom_kill 0"),
    )
    correlator.record_snapshot_pair(snap_t0, snap_t1)

    span = Span(
        trace_id="trace-app-lock",
        span_id="span-lock",
        parent_span_id=None,
        service_name="order-svc",
        operation_name="AcquireDistributedLock",
        start_time_ns=1_200_000_000,
        end_time_ns=1_800_000_000,
        container_id="container-healthy",
    )
    report = correlator.correlate_span(span)
    assert report.root_cause == RootCauseCategory.APPLICATION_BOUND
    assert report.oom_killed is False
    assert report.enriched_span.has_container_anomaly is False
