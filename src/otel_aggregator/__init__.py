"""
otel-ebpf-span-aggregator
~~~~~~~~~~~~~~~~~~~~~~~~~

High-throughput OpenTelemetry distributed trace collector, tail-based sampling
engine, DDSketch relative-error quantile sketch, and Linux cgroup v2 / eBPF
container telemetry correlator.

:copyright: (c) 2026 by Abdullah Azmi.
:license: MIT, see LICENSE for more details.
"""

from .ddsketch import DDSketch, DenseStore
from .tail_sampler import (
    Span,
    SpanStatus,
    TraceDAG,
    SamplingDecision,
    SamplingReason,
    TailSamplingConfig,
    TailSamplingEngine,
    fnv1a_64,
)
from .cgroup_correlator import (
    CpuStatSnapshot,
    PsiMetric,
    MemoryPressureSnapshot,
    MemoryEventsSnapshot,
    ContainerCgroupSnapshot,
    CgroupWindowDelta,
    RootCauseCategory,
    SpanCorrelationReport,
    CgroupSpanCorrelator,
    parse_cpu_stat,
    parse_memory_pressure,
    parse_memory_events,
)

__all__ = [
    "DDSketch",
    "DenseStore",
    "Span",
    "SpanStatus",
    "TraceDAG",
    "SamplingDecision",
    "SamplingReason",
    "TailSamplingConfig",
    "TailSamplingEngine",
    "fnv1a_64",
    "CpuStatSnapshot",
    "PsiMetric",
    "MemoryPressureSnapshot",
    "MemoryEventsSnapshot",
    "ContainerCgroupSnapshot",
    "CgroupWindowDelta",
    "RootCauseCategory",
    "SpanCorrelationReport",
    "CgroupSpanCorrelator",
    "parse_cpu_stat",
    "parse_memory_pressure",
    "parse_memory_events",
]

__version__ = "0.2.0"
__author__ = "Abdullah Azmi"

from .diagnostics import run_diagnostic_suite, validate_runtime_invariants
__all__ = list(__all__) + ["run_diagnostic_suite", "validate_runtime_invariants"]
