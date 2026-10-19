"""
Linux cgroup v2 & eBPF Container Telemetry Correlator.

Parses kernel cgroup v2 virtual files (`cpu.stat`, `memory.pressure`,
`memory.events`) alongside container runtime exit statuses (`exitCode=137` /
`SIGKILL`), computes sliding-window resource pressure deltas, and attributes
OpenTelemetry span latency regressions to kernel-level CFS throttling, memory
reclaim PSI stalls, or OOM kills.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from .tail_sampler import Span


@dataclass(frozen=True)
class CpuStatSnapshot:
    """Parsed representation of `/sys/fs/cgroup/<pod>/cpu.stat` (cgroup v2)."""

    usage_usec: int = 0
    user_usec: int = 0
    system_usec: int = 0
    nr_periods: int = 0
    nr_throttled: int = 0
    throttled_usec: int = 0


@dataclass(frozen=True)
class PsiMetric:
    """Single PSI line (`some` or `full`) from `/sys/fs/cgroup/<pod>/memory.pressure`."""

    avg10: float = 0.0
    avg60: float = 0.0
    avg300: float = 0.0
    total_usec: int = 0


@dataclass(frozen=True)
class MemoryPressureSnapshot:
    """Parsed PSI snapshot containing both `some` and `full` stall metrics."""

    some: PsiMetric = field(default_factory=PsiMetric)
    full: PsiMetric = field(default_factory=PsiMetric)


@dataclass(frozen=True)
class MemoryEventsSnapshot:
    """Parsed `/sys/fs/cgroup/<pod>/memory.events` counters."""

    low: int = 0
    high: int = 0
    max: int = 0
    oom: int = 0
    oom_kill: int = 0


@dataclass(frozen=True)
class ContainerCgroupSnapshot:
    """Point-in-time container cgroup v2 telemetry sample."""

    container_id: str
    timestamp_ns: int
    cpu_stat: CpuStatSnapshot
    memory_pressure: MemoryPressureSnapshot
    memory_events: MemoryEventsSnapshot
    last_exit_code: Optional[int] = None


@dataclass(frozen=True)
class CgroupWindowDelta:
    """Resource pressure delta computed across `[t0, t1]` for a container."""

    container_id: str
    start_time_ns: int
    end_time_ns: int
    delta_nr_periods: int
    delta_nr_throttled: int
    delta_throttled_usec: int
    delta_psi_some_usec: int
    delta_psi_full_usec: int
    delta_high_events: int
    delta_oom_kills: int
    exit_code_137_detected: bool

    @property
    def throttle_ratio(self) -> float:
        if self.delta_nr_periods <= 0:
            return 0.0
        return self.delta_nr_throttled / float(self.delta_nr_periods)

    @property
    def throttled_ms(self) -> float:
        return self.delta_throttled_usec / 1000.0

    @property
    def psi_some_stall_ms(self) -> float:
        return self.delta_psi_some_usec / 1000.0

    @property
    def psi_full_stall_ms(self) -> float:
        return self.delta_psi_full_usec / 1000.0


class RootCauseCategory(str, Enum):
    OOM_KILLED = "OOM_KILLED"
    MEMORY_PSI_STALL = "MEMORY_PSI_STALL"
    CPU_CFS_THROTTLED = "CPU_CFS_THROTTLED"
    APPLICATION_BOUND = "APPLICATION_BOUND"


@dataclass(frozen=True)
class SpanCorrelationReport:
    """Attribution report linking a slow/erroneous span to container cgroup v2 signals."""

    span_id: str
    trace_id: str
    container_id: str
    span_duration_ms: float
    root_cause: RootCauseCategory
    throttle_ratio: float
    throttled_ms: float
    psi_full_stall_ms: float
    oom_killed: bool
    severity_score: float
    enriched_span: Span


def parse_cpu_stat(raw_text: str) -> CpuStatSnapshot:
    """Parse Linux cgroup v2 `cpu.stat` content."""
    fields: Dict[str, int] = {}
    for line in raw_text.strip().splitlines():
        parts = line.strip().split()
        if len(parts) == 2:
            fields[parts[0]] = int(parts[1])
    return CpuStatSnapshot(
        usage_usec=fields.get("usage_usec", 0),
        user_usec=fields.get("user_usec", 0),
        system_usec=fields.get("system_usec", 0),
        nr_periods=fields.get("nr_periods", 0),
        nr_throttled=fields.get("nr_throttled", 0),
        throttled_usec=fields.get("throttled_usec", 0),
    )


def parse_memory_pressure(raw_text: str) -> MemoryPressureSnapshot:
    """
    Parse Linux PSI format (`memory.pressure`):
      some avg10=1.25 avg60=0.80 avg300=0.10 total=450120
      full avg10=0.40 avg60=0.20 avg300=0.05 total=120400
    """
    some_metric = PsiMetric()
    full_metric = PsiMetric()

    for line in raw_text.strip().splitlines():
        tokens = line.strip().split()
        if not tokens:
            continue
        kind = tokens[0]
        kv: Dict[str, str] = {}
        for token in tokens[1:]:
            if "=" in token:
                k, v = token.split("=", 1)
                kv[k] = v
        metric = PsiMetric(
            avg10=float(kv.get("avg10", 0.0)),
            avg60=float(kv.get("avg60", 0.0)),
            avg300=float(kv.get("avg300", 0.0)),
            total_usec=int(kv.get("total", 0)),
        )
        if kind == "some":
            some_metric = metric
        elif kind == "full":
            full_metric = metric

    return MemoryPressureSnapshot(some=some_metric, full=full_metric)


def parse_memory_events(raw_text: str) -> MemoryEventsSnapshot:
    """Parse Linux cgroup v2 `memory.events` content."""
    fields: Dict[str, int] = {}
    for line in raw_text.strip().splitlines():
        parts = line.strip().split()
        if len(parts) == 2:
            fields[parts[0]] = int(parts[1])
    return MemoryEventsSnapshot(
        low=fields.get("low", 0),
        high=fields.get("high", 0),
        max=fields.get("max", 0),
        oom=fields.get("oom", 0),
        oom_kill=fields.get("oom_kill", 0),
    )


class CgroupSpanCorrelator:
    """
    Correlates OpenTelemetry spans against container cgroup v2 telemetry windows
    and enriches spans with deterministic kernel pressure attributes.
    """

    def __init__(
        self,
        throttle_ratio_threshold: float = 0.15,
        psi_full_stall_threshold_ms: float = 10.0,
    ) -> None:
        self.throttle_ratio_threshold = throttle_ratio_threshold
        self.psi_full_stall_threshold_ms = psi_full_stall_threshold_ms
        self._deltas_by_container: Dict[str, List[CgroupWindowDelta]] = {}

    @staticmethod
    def compute_window_delta(
        before: ContainerCgroupSnapshot,
        after: ContainerCgroupSnapshot,
    ) -> CgroupWindowDelta:
        if before.container_id != after.container_id:
            raise ValueError("Container IDs must match when computing cgroup delta")
        if after.timestamp_ns < before.timestamp_ns:
            raise ValueError("after.timestamp_ns must be >= before.timestamp_ns")

        delta_oom_kills = max(0, after.memory_events.oom_kill - before.memory_events.oom_kill)
        exit_137 = after.last_exit_code == 137 or delta_oom_kills > 0

        return CgroupWindowDelta(
            container_id=before.container_id,
            start_time_ns=before.timestamp_ns,
            end_time_ns=after.timestamp_ns,
            delta_nr_periods=max(0, after.cpu_stat.nr_periods - before.cpu_stat.nr_periods),
            delta_nr_throttled=max(0, after.cpu_stat.nr_throttled - before.cpu_stat.nr_throttled),
            delta_throttled_usec=max(
                0, after.cpu_stat.throttled_usec - before.cpu_stat.throttled_usec
            ),
            delta_psi_some_usec=max(
                0,
                after.memory_pressure.some.total_usec - before.memory_pressure.some.total_usec,
            ),
            delta_psi_full_usec=max(
                0,
                after.memory_pressure.full.total_usec - before.memory_pressure.full.total_usec,
            ),
            delta_high_events=max(0, after.memory_events.high - before.memory_events.high),
            delta_oom_kills=delta_oom_kills,
            exit_code_137_detected=exit_137,
        )

    def record_snapshot_pair(
        self,
        before: ContainerCgroupSnapshot,
        after: ContainerCgroupSnapshot,
    ) -> CgroupWindowDelta:
        delta = self.compute_window_delta(before, after)
        windows = self._deltas_by_container.setdefault(delta.container_id, [])
        windows.append(delta)
        return delta

    def correlate_span(self, span: Span) -> SpanCorrelationReport:
        """
        Match `span` to overlapping cgroup v2 windows for `span.container_id`,
        classify the root cause of latency/termination, and return an enriched span.
        """
        cid = span.container_id or "unknown"
        windows = self._deltas_by_container.get(cid, [])

        overlapping = [
            w
            for w in windows
            if w.start_time_ns <= span.end_time_ns and w.end_time_ns >= span.start_time_ns
        ]

        if not overlapping:
            return SpanCorrelationReport(
                span_id=span.span_id,
                trace_id=span.trace_id,
                container_id=cid,
                span_duration_ms=span.duration_ms,
                root_cause=RootCauseCategory.APPLICATION_BOUND,
                throttle_ratio=0.0,
                throttled_ms=0.0,
                psi_full_stall_ms=0.0,
                oom_killed=False,
                severity_score=0.0,
                enriched_span=span,
            )

        max_throttle_ratio = max(w.throttle_ratio for w in overlapping)
        total_throttled_ms = sum(w.throttled_ms for w in overlapping)
        total_psi_full_ms = sum(w.psi_full_stall_ms for w in overlapping)
        oom_killed = any(w.exit_code_137_detected for w in overlapping)

        new_attrs = dict(span.attributes)
        new_attrs["cgroup.throttle_ratio"] = f"{max_throttle_ratio:.4f}"
        new_attrs["cgroup.throttled_ms"] = f"{total_throttled_ms:.2f}"
        new_attrs["cgroup.psi_full_ms"] = f"{total_psi_full_ms:.2f}"

        if oom_killed:
            root_cause = RootCauseCategory.OOM_KILLED
            new_attrs["cgroup.oom_kill"] = "true"
            new_attrs["container.exit_code"] = "137"
            severity = 1.0
        elif total_psi_full_ms >= self.psi_full_stall_threshold_ms:
            root_cause = RootCauseCategory.MEMORY_PSI_STALL
            new_attrs["cgroup.psi_stall"] = "true"
            severity = min(0.95, 0.5 + (total_psi_full_ms / max(1.0, span.duration_ms)) * 0.5)
        elif max_throttle_ratio >= self.throttle_ratio_threshold:
            root_cause = RootCauseCategory.CPU_CFS_THROTTLED
            new_attrs["cgroup.throttled"] = "true"
            severity = min(0.90, max_throttle_ratio)
        else:
            root_cause = RootCauseCategory.APPLICATION_BOUND
            severity = 0.05

        enriched = Span(
            trace_id=span.trace_id,
            span_id=span.span_id,
            parent_span_id=span.parent_span_id,
            service_name=span.service_name,
            operation_name=span.operation_name,
            start_time_ns=span.start_time_ns,
            end_time_ns=span.end_time_ns,
            status=span.status,
            http_status_code=span.http_status_code,
            container_id=span.container_id,
            attributes=new_attrs,
        )

        return SpanCorrelationReport(
            span_id=span.span_id,
            trace_id=span.trace_id,
            container_id=cid,
            span_duration_ms=span.duration_ms,
            root_cause=root_cause,
            throttle_ratio=max_throttle_ratio,
            throttled_ms=total_throttled_ms,
            psi_full_stall_ms=total_psi_full_ms,
            oom_killed=oom_killed,
            severity_score=round(severity, 4),
            enriched_span=enriched,
        )
