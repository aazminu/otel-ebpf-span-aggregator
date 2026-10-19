"""
Trace-Aware Tail-Based Sampling Engine & DAG Reconstructor.

Assembles distributed OpenTelemetry spans into directed acyclic graphs (DAGs)
keyed by `trace_id`, tracks per-service latency distributions using DDSketch,
and executes deterministic multi-criteria tail sampling:
  1. Error Propagation Retention: Any span in the trace DAG with `SpanStatus.ERROR`
     or HTTP status >= 500 forces 100% trace retention.
  2. Container Anomaly Retention: Any span flagged with cgroup v2 CPU throttling,
     PSI stall, or OOM kill forces 100% trace retention.
  3. High-Latency Outlier Retention: Traces whose root duration exceeds static SLA
     or dynamic per-service DDSketch p99 latency threshold are retained.
  4. Consistent FNV-1a 64-bit Hash Sampling: Normal baseline traces are sampled
     deterministically via `fnv1a_64(trace_id) / 2^64 < baseline_sample_rate`,
     guaranteeing multi-collector agreement without cross-node coordination.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from .ddsketch import DDSketch

FNV64_OFFSET_BASIS = 0xCBF29CE484222325
FNV64_PRIME = 0x100000001B3
UINT64_MAX = 0xFFFFFFFFFFFFFFFF


def fnv1a_64(data: str) -> int:
    """Compute deterministic 64-bit FNV-1a hash of a trace ID string."""
    h = FNV64_OFFSET_BASIS
    for byte in data.encode("utf-8"):
        h ^= byte
        h = (h * FNV64_PRIME) & UINT64_MAX
    return h


def deterministic_sample_score(trace_id: str) -> float:
    """
    Map `trace_id` uniformly and deterministically to [0.0, 1.0) using 64-bit
    FNV-1a followed by a SplitMix64/Stafford13 bit-avalanche finalizer so
    sequentially suffixed trace IDs distribute uniformly across [0, 1).
    """
    z = fnv1a_64(trace_id)
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & UINT64_MAX
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & UINT64_MAX
    z = (z ^ (z >> 31)) & UINT64_MAX
    return z / float(UINT64_MAX + 1)


class SpanStatus( str, Enum ):
    UNSET = "UNSET"
    OK = "OK"
    ERROR = "ERROR"


class SamplingReason( str, Enum ):
    ERROR_SPAN = "ERROR_SPAN"
    CONTAINER_PRESSURE = "CONTAINER_PRESSURE"
    LATENCY_OUTLIER_STATIC = "LATENCY_OUTLIER_STATIC"
    LATENCY_OUTLIER_P99 = "LATENCY_OUTLIER_P99"
    BASELINE_HASH_SAMPLED = "BASELINE_HASH_SAMPLED"
    DROPPED_BASELINE = "DROPPED_BASELINE"


@dataclass(frozen=True)
class Span:
    """OpenTelemetry-compatible immutable span representation."""

    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    service_name: str
    operation_name: str
    start_time_ns: int
    end_time_ns: int
    status: SpanStatus = SpanStatus.OK
    http_status_code: Optional[int] = None
    container_id: Optional[str] = None
    attributes: Dict[str, str] = field(default_factory=dict)

    @property
    def duration_ns(self) -> int:
        return max(0, self.end_time_ns - self.start_time_ns)

    @property
    def duration_ms(self) -> float:
        return self.duration_ns / 1_000_000.0

    @property
    def is_error(self) -> bool:
        if self.status == SpanStatus.ERROR:
            return True
        if self.http_status_code is not None and self.http_status_code >= 500:
            return True
        if self.attributes.get("error", "").lower() == "true":
            return True
        return False

    @property
    def has_container_anomaly(self) -> bool:
        return (
            self.attributes.get("cgroup.throttled", "false").lower() == "true"
            or self.attributes.get("cgroup.oom_kill", "false").lower() == "true"
            or self.attributes.get("cgroup.psi_stall", "false").lower() == "true"
        )


class TraceDAG:
    """
    Reconstructs a multi-span distributed trace DAG, tracks parent-child edges,
    identifies orphan spans, and computes end-to-end critical path latency.
    """

    def __init__(self, trace_id: str) -> None:
        self.trace_id: str = trace_id
        self.spans_by_id: Dict[str, Span] = {}
        self.children_map: Dict[str, List[str]] = {}
        self.first_seen_ns: Optional[int] = None
        self.last_updated_ns: Optional[int] = None

    def add_span(self, span: Span) -> None:
        if span.trace_id != self.trace_id:
            raise ValueError(
                f"Span trace_id {span.trace_id} does not match TraceDAG {self.trace_id}"
            )
        self.spans_by_id[span.span_id] = span
        if span.parent_span_id is not None:
            children = self.children_map.setdefault(span.parent_span_id, [])
            if span.span_id not in children:
                children.append(span.span_id)

        if self.first_seen_ns is None or span.start_time_ns < self.first_seen_ns:
            self.first_seen_ns = span.start_time_ns
        if self.last_updated_ns is None or span.end_time_ns > self.last_updated_ns:
            self.last_updated_ns = span.end_time_ns

    @property
    def span_count(self) -> int:
        return len(self.spans_by_id)

    @property
    def root_span(self) -> Optional[Span]:
        for span in self.spans_by_id.values():
            if span.parent_span_id is None:
                return span
        return None

    @property
    def orphan_span_ids(self) -> List[str]:
        """Return span IDs whose parent_span_id is non-null but absent from the DAG."""
        orphans: List[str] = []
        for span in self.spans_by_id.values():
            if span.parent_span_id is not None and span.parent_span_id not in self.spans_by_id:
                orphans.append(span.span_id)
        return sorted(orphans)

    @property
    def has_error(self) -> bool:
        return any(s.is_error for s in self.spans_by_id.values())

    @property
    def has_container_anomaly(self) -> bool:
        return any(s.has_container_anomaly for s in self.spans_by_id.values())

    @property
    def error_services(self) -> Set[str]:
        return {s.service_name for s in self.spans_by_id.values() if s.is_error}

    @property
    def trace_duration_ms(self) -> float:
        """
        End-to-end trace duration in milliseconds: uses root span duration when
        present, or `[min(start_time_ns), max(end_time_ns)]` across all spans.
        """
        root = self.root_span
        if root is not None:
            return root.duration_ms
        if self.first_seen_ns is None or self.last_updated_ns is None:
            return 0.0
        return max(0, self.last_updated_ns - self.first_seen_ns) / 1_000_000.0

    def critical_path_ms(self) -> float:
        """
        Compute the longest causal chain duration (in ms) from root (or any top-level
        available span) down through its descendant tree.
        """
        if not self.spans_by_id:
            return 0.0

        memo: Dict[str, float] = {}
        visiting: Set[str] = set()

        def dfs(span_id: str) -> float:
            if span_id in memo:
                return memo[span_id]
            if span_id in visiting:
                return 0.0
            visiting.add(span_id)
            span = self.spans_by_id[span_id]
            child_ids = [
                cid for cid in self.children_map.get(span_id, []) if cid in self.spans_by_id
            ]
            max_child = max((dfs(cid) for cid in child_ids), default=0.0)
            # Exclusive work on this span plus longest child branch, bounded below by span duration
            total = max(span.duration_ms, max_child)
            visiting.remove(span_id)
            memo[span_id] = total
            return total

        return max(dfs(sid) for sid in self.spans_by_id)


@dataclass(frozen=True)
class SamplingDecision:
    trace_id: str
    sampled: bool
    reason: SamplingReason
    span_count: int
    trace_duration_ms: float
    error_services: Tuple[str, ...]


@dataclass
class TailSamplingConfig:
    """Configuration for the trace-aware tail-based sampling engine."""

    baseline_sample_rate: float = 0.05
    static_latency_threshold_ms: float = 500.0
    enable_dynamic_p99_outlier: bool = True
    min_samples_for_dynamic_p99: int = 20
    dynamic_p99_multiplier: float = 1.05
    max_in_flight_traces: int = 4096
    ddsketch_relative_accuracy: float = 0.01


class TailSamplingEngine:
    """
    Bounded-memory tail-based trace sampler combining per-service DDSketch latency
    distributions with DAG-wide error and container anomaly propagation.
    """

    def __init__(self, config: Optional[TailSamplingConfig] = None) -> None:
        self.config: TailSamplingConfig = config or TailSamplingConfig()
        self.in_flight_traces: OrderedDict[str, TraceDAG] = OrderedDict()
        self.service_latency_sketches: Dict[str, DDSketch] = {}
        self.evicted_decisions: List[SamplingDecision] = []
        self.total_spans_ingested: int = 0

    def ingest_span(self, span: Span) -> Optional[SamplingDecision]:
        """
        Ingest a span into the active trace ring buffer and update the per-service
        DDSketch latency histogram BEFORE sampling so metrics remain un-biased.
        If the ring buffer exceeds `max_in_flight_traces`, the oldest trace is
        evicted, evaluated, and its `SamplingDecision` returned.
        """
        self.total_spans_ingested += 1

        # Record un-sampled latency in service DDSketch (metrics before dropping!)
        sketch = self.service_latency_sketches.get(span.service_name)
        if sketch is None:
            sketch = DDSketch(relative_accuracy=self.config.ddsketch_relative_accuracy)
            self.service_latency_sketches[span.service_name] = sketch
        sketch.add(span.duration_ms)

        evicted_decision: Optional[SamplingDecision] = None
        if (
            span.trace_id not in self.in_flight_traces
            and len(self.in_flight_traces) >= self.config.max_in_flight_traces
        ):
            oldest_trace_id, oldest_dag = self.in_flight_traces.popitem(last=False)
            evicted_decision = self._evaluate_dag(oldest_dag)
            self.evicted_decisions.append(evicted_decision)

        dag = self.in_flight_traces.get(span.trace_id)
        if dag is None:
            dag = TraceDAG(span.trace_id)
            self.in_flight_traces[span.trace_id] = dag
        else:
            # Refresh LRU ordering
            self.in_flight_traces.move_to_end(span.trace_id)

        dag.add_span(span)
        return evicted_decision

    def evaluate_and_flush(self, trace_id: str) -> SamplingDecision:
        """Finalize a trace DAG, remove it from the in-flight buffer, and return decision."""
        dag = self.in_flight_traces.pop(trace_id, None)
        if dag is None:
            raise KeyError(f"Trace {trace_id} not found in in-flight buffer")
        return self._evaluate_dag(dag)

    def flush_all(self) -> List[SamplingDecision]:
        """Evaluate and flush all remaining in-flight traces."""
        decisions: List[SamplingDecision] = []
        while self.in_flight_traces:
            _, dag = self.in_flight_traces.popitem(last=False)
            decisions.append(self._evaluate_dag(dag))
        return decisions

    def _evaluate_dag(self, dag: TraceDAG) -> SamplingDecision:
        duration_ms = dag.trace_duration_ms
        err_services = tuple(sorted(dag.error_services))

        # Priority 1: Error propagation anywhere in the trace DAG
        if dag.has_error:
            return SamplingDecision(
                trace_id=dag.trace_id,
                sampled=True,
                reason=SamplingReason.ERROR_SPAN,
                span_count=dag.span_count,
                trace_duration_ms=duration_ms,
                error_services=err_services,
            )

        # Priority 2: Container cgroup v2 throttling / PSI / OOM anomaly
        if dag.has_container_anomaly:
            return SamplingDecision(
                trace_id=dag.trace_id,
                sampled=True,
                reason=SamplingReason.CONTAINER_PRESSURE,
                span_count=dag.span_count,
                trace_duration_ms=duration_ms,
                error_services=err_services,
            )

        # Priority 3: Static SLA latency outlier
        if duration_ms >= self.config.static_latency_threshold_ms:
            return SamplingDecision(
                trace_id=dag.trace_id,
                sampled=True,
                reason=SamplingReason.LATENCY_OUTLIER_STATIC,
                span_count=dag.span_count,
                trace_duration_ms=duration_ms,
                error_services=err_services,
            )

        # Priority 4: Dynamic per-service DDSketch p99 latency outlier
        if self.config.enable_dynamic_p99_outlier:
            for span in dag.spans_by_id.values():
                sketch = self.service_latency_sketches.get(span.service_name)
                if sketch is not None and sketch.count >= self.config.min_samples_for_dynamic_p99:
                    p99_val = sketch.p99
                    if (
                        p99_val is not None
                        and span.duration_ms >= p99_val * self.config.dynamic_p99_multiplier
                    ):
                        return SamplingDecision(
                            trace_id=dag.trace_id,
                            sampled=True,
                            reason=SamplingReason.LATENCY_OUTLIER_P99,
                            span_count=dag.span_count,
                            trace_duration_ms=duration_ms,
                            error_services=err_services,
                        )

        # Priority 5: Deterministic trace-ID consistent FNV-1a hash sampling
        score = deterministic_sample_score(dag.trace_id)
        if score < self.config.baseline_sample_rate:
            return SamplingDecision(
                trace_id=dag.trace_id,
                sampled=True,
                reason=SamplingReason.BASELINE_HASH_SAMPLED,
                span_count=dag.span_count,
                trace_duration_ms=duration_ms,
                error_services=err_services,
            )

        return SamplingDecision(
            trace_id=dag.trace_id,
            sampled=False,
            reason=SamplingReason.DROPPED_BASELINE,
            span_count=dag.span_count,
            trace_duration_ms=duration_ms,
            error_services=err_services,
        )
