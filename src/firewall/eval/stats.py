"""Bootstrap confidence intervals (numpy, deterministic seed)."""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np


def bootstrap_ci(values: Sequence[float | bool], *, n: int = 10000, alpha: float = 0.05,
                 seed: int = 0) -> tuple[float, float]:
    """Percentile bootstrap CI of the mean over cases; degenerate inputs give (mean, mean)."""
    arr = np.asarray([float(v) for v in values], dtype=float)
    if arr.size == 0:
        return (float("nan"), float("nan"))
    if arr.size == 1 or np.all(arr == arr[0]):
        return (float(arr[0]) if arr.size == 1 else float(arr.mean()),) * 2  # type: ignore[return-value]
    rng = np.random.default_rng(seed)
    means = arr[rng.integers(0, arr.size, size=(n, arr.size))].mean(axis=1)
    lo, hi = np.quantile(means, [alpha / 2, 1 - alpha / 2])
    return float(lo), float(hi)
