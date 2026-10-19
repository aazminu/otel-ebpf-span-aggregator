"""
DDSketch: A Fast and Fully-Mergeable Quantile Sketch with Relative-Error Guarantees.

Reference:
    Charles Masson, Jee E. Rim, and Homin K. Lee (Datadog). 2019.
    "DDSketch: A Fast and Fully-Mergeable Quantile Sketch with Relative-Error Guarantees."
    Proceedings of the VLDB Endowment, Vol. 12, No. 12, pp. 2195-2205.

Mathematical Guarantee:
    Given target relative accuracy alpha in (0, 1), define:
        gamma = (1 + alpha) / (1 - alpha)
    Every positive observation x > min_indexable_value is mapped to bucket index:
        k(x) = ceil(log_gamma(x))
    And reconstructed via representative value:
        v(k) = 2 * gamma^k / (gamma + 1)
    Because gamma^(k-1) < x <= gamma^k, the reconstructed quantile q_hat satisfies:
        |q_hat - q_true| <= alpha * q_true
    for all quantiles simultaneously, and sketches merge associatively in O(B) time
    where B is the number of active logarithmic bins.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional


@dataclass
class DenseStore:
    """
    Bounded logarithmic bucket store with automatic lowest-bucket collapsing
    when the number of active bins exceeds `max_bins`.
    """

    max_bins: int = 2048
    bins: Dict[int, int] = field(default_factory=dict)
    total_count: int = 0

    def __post_init__(self) -> None:
        if self.max_bins < 8:
            raise ValueError("max_bins must be at least 8")

    def add(self, index: int, weight: int = 1) -> None:
        if weight <= 0:
            raise ValueError("weight must be a positive integer")
        self.bins[index] = self.bins.get(index, 0) + weight
        self.total_count += weight
        self._collapse_if_needed()

    def _collapse_if_needed(self) -> None:
        """
        Collapse the lowest-indexed buckets into the next lowest bucket when
        active bin cardinality exceeds `max_bins`, preserving high-quantile
        (p95/p99/p99.9) relative accuracy.
        """
        while len(self.bins) > self.max_bins:
            sorted_keys = sorted(self.bins.keys())
            lowest_k = sorted_keys[0]
            second_k = sorted_keys[1]
            count_to_move = self.bins.pop(lowest_k)
            self.bins[second_k] += count_to_move

    def merge(self, other: DenseStore) -> None:
        if other.total_count == 0:
            return
        for idx, count in other.bins.items():
            self.bins[idx] = self.bins.get(idx, 0) + count
        self.total_count += other.total_count
        self._collapse_if_needed()

    def copy(self) -> DenseStore:
        cloned = DenseStore(max_bins=self.max_bins)
        cloned.bins = dict(self.bins)
        cloned.total_count = self.total_count
        return cloned


class DDSketch:
    """
    Distributed relative-error quantile sketch for high-dynamic-range latency telemetry.

    Parameters
    ----------
    relative_accuracy : float
        Target relative error alpha in (0, 1). Default 0.01 (1% relative error).
    max_bins : int
        Maximum number of logarithmic buckets per polarity store before lowest-bin
        collapsing occurs. Default 2048.
    min_indexable_value : float
        Smallest positive value mapped to a logarithmic bucket; values with
        |x| <= min_indexable_value are accumulated in `zero_count`.
    """

    def __init__(
        self,
        relative_accuracy: float = 0.01,
        max_bins: int = 2048,
        min_indexable_value: float = 1e-9,
    ) -> None:
        if not (0.0 < relative_accuracy < 1.0):
            raise ValueError("relative_accuracy (alpha) must be strictly in (0, 1)")
        if min_indexable_value <= 0.0:
            raise ValueError("min_indexable_value must be strictly positive")

        self.alpha: float = float(relative_accuracy)
        self.gamma: float = (1.0 + self.alpha) / (1.0 - self.alpha)
        self.ln_gamma: float = math.log(self.gamma)
        self.min_indexable_value: float = float(min_indexable_value)
        self.max_bins: int = max_bins

        self.positive_store: DenseStore = DenseStore(max_bins=max_bins)
        self.negative_store: DenseStore = DenseStore(max_bins=max_bins)
        self.zero_count: int = 0

        self._count: int = 0
        self._sum: float = 0.0
        self._min: float = math.inf
        self._max: float = -math.inf

    @property
    def relative_error_bound(self) -> float:
        return self.alpha

    @property
    def count(self) -> int:
        return self._count

    @property
    def sum(self) -> float:
        return self._sum

    @property
    def avg(self) -> float:
        if self._count == 0:
            return 0.0
        return self._sum / self._count

    @property
    def min_value(self) -> Optional[float]:
        return None if self._count == 0 else self._min

    @property
    def max_value(self) -> Optional[float]:
        return None if self._count == 0 else self._max

    def key(self, value: float) -> int:
        """Map a strictly positive value to its integer logarithmic bucket index."""
        if value <= self.min_indexable_value:
            return math.ceil(math.log(self.min_indexable_value) / self.ln_gamma)
        return math.ceil(math.log(value) / self.ln_gamma)

    def value_from_key(self, index: int) -> float:
        """
        Compute the midpoint representative value for bucket index `k` such that
        maximum relative error across (gamma^(k-1), gamma^k] is bounded by alpha.
        """
        return (2.0 * math.pow(self.gamma, index)) / (self.gamma + 1.0)

    def add(self, value: float, weight: int = 1) -> None:
        """Record a sample `value` with integer multiplicity `weight`."""
        if math.isnan(value) or math.isinf(value):
            raise ValueError("DDSketch does not accept NaN or infinite values")
        if weight <= 0:
            raise ValueError("weight must be >= 1")

        if value > self.min_indexable_value:
            self.positive_store.add(self.key(value), weight)
        elif value < -self.min_indexable_value:
            self.negative_store.add(self.key(-value), weight)
        else:
            self.zero_count += weight

        self._count += weight
        self._sum += value * weight
        if value < self._min:
            self._min = value
        if value > self._max:
            self._max = value

    def add_batch(self, values: Iterable[float]) -> None:
        """Insert a batch of observations into the sketch."""
        for v in values:
            self.add(v, 1)

    def merge(self, other: DDSketch) -> None:
        """
        Merge another DDSketch with matching `alpha` into this instance in-place.
        Associative and commutative across distributed trace-agent shards.
        """
        if not math.isclose(self.alpha, other.alpha, rel_tol=1e-9):
            raise ValueError(
                f"Cannot merge DDSketches with different relative_accuracy: "
                f"{self.alpha} vs {other.alpha}"
            )
        if other._count == 0:
            return

        self.positive_store.merge(other.positive_store)
        self.negative_store.merge(other.negative_store)
        self.zero_count += other.zero_count
        self._count += other._count
        self._sum += other._sum
        if other._min < self._min:
            self._min = other._min
        if other._max > self._max:
            self._max = other._max

    def quantile(self, q: float) -> Optional[float]:
        """
        Estimate the `q`-th quantile for q in [0, 1] with alpha-relative error guarantee.
        Returns None if the sketch is empty.
        """
        if not (0.0 <= q <= 1.0):
            raise ValueError("Quantile q must be in [0.0, 1.0]")
        if self._count == 0:
            return None
        if q == 0.0:
            return self._min
        if q == 1.0:
            return self._max

        target_rank = q * (self._count - 1)

        if target_rank < self.negative_store.total_count:
            # Traverse negative buckets from highest magnitude (most negative) to lowest
            cumulative = 0
            for idx in sorted(self.negative_store.bins.keys(), reverse=True):
                cumulative += self.negative_store.bins[idx]
                if cumulative > target_rank:
                    return -self.value_from_key(idx)

        if target_rank < self.negative_store.total_count + self.zero_count:
            return 0.0

        pos_target = target_rank - self.negative_store.total_count - self.zero_count
        cumulative = 0
        for idx in sorted(self.positive_store.bins.keys()):
            cumulative += self.positive_store.bins[idx]
            if cumulative > pos_target:
                return self.value_from_key(idx)

        return self._max

    def quantiles(self, qs: Iterable[float]) -> List[Optional[float]]:
        """Query multiple quantiles in a single call."""
        return [self.quantile(q) for q in qs]

    @property
    def p50(self) -> Optional[float]:
        return self.quantile(0.50)

    @property
    def p95(self) -> Optional[float]:
        return self.quantile(0.95)

    @property
    def p99(self) -> Optional[float]:
        return self.quantile(0.99)

    def summary_dict(self) -> Dict[str, Optional[float]]:
        """Export Datadog APM-compatible distribution summary metrics."""
        return {
            "count": float(self._count),
            "sum": self._sum,
            "avg": self.avg,
            "min": self.min_value,
            "max": self.max_value,
            "p50": self.p50,
            "p95": self.p95,
            "p99": self.p99,
        }
