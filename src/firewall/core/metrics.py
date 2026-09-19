"""Runtime metrics: verdict/rule counters and latency reservoirs with percentiles + Prometheus text."""

from __future__ import annotations

import threading
from collections import Counter, deque
from typing import Any, Literal

from firewall.core.models import Decision

Series = Literal["eval_us", "label_us", "http_ms"]
RESERVOIR = 100_000


def percentile(sorted_values: list[float], q: float) -> float:
    """Nearest-rank-with-interpolation percentile on a sorted list (q in [0, 100])."""
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    pos = (len(sorted_values) - 1) * q / 100.0
    lo = int(pos)
    hi = min(lo + 1, len(sorted_values) - 1)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (pos - lo)


class GatewayMetrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.verdicts: Counter[str] = Counter()
        self.tools: Counter[str] = Counter()
        self.rules: Counter[str] = Counter()
        self._series: dict[str, deque[float]] = {s: deque(maxlen=RESERVOIR) for s in ("eval_us", "label_us", "http_ms")}
        self.http_routes: Counter[str] = Counter()

    def observe_decision(self, d: Decision) -> None:
        with self._lock:
            self.verdicts[d.verdict.value] += 1
            self.tools[d.tool] += 1
            for rid in d.rule_ids:
                self.rules[rid] += 1
            self._series["eval_us"].append(d.eval_us)

    def observe_label(self, label_us: float) -> None:
        with self._lock:
            self._series["label_us"].append(label_us)

    def observe_http(self, route: str, ms: float) -> None:
        with self._lock:
            self.http_routes[route] += 1
            self._series["http_ms"].append(ms)

    def percentiles(self, series: Series) -> dict[str, float]:
        with self._lock:
            values = sorted(self._series[series])
        return {"p50": percentile(values, 50), "p95": percentile(values, 95), "p99": percentile(values, 99),
                "max": values[-1] if values else 0.0, "n": float(len(values))}

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            out: dict[str, Any] = {"verdicts": dict(self.verdicts), "tools": dict(self.tools),
                                   "rules": dict(self.rules), "http_routes": dict(self.http_routes)}
        for s in ("eval_us", "label_us", "http_ms"):
            out[s] = self.percentiles(s)  # type: ignore[arg-type]
        return out

    def prometheus_text(self) -> str:
        snap = self.snapshot()
        lines = ["# TYPE fw_decisions_total counter"]
        lines += [f'fw_decisions_total{{verdict="{v}"}} {n}' for v, n in sorted(snap["verdicts"].items())]
        lines.append("# TYPE fw_rule_hits_total counter")
        lines += [f'fw_rule_hits_total{{rule="{r}"}} {n}' for r, n in sorted(snap["rules"].items())]
        for series, metric in (("eval_us", "fw_eval_us"), ("label_us", "fw_label_us"), ("http_ms", "fw_http_ms")):
            lines.append(f"# TYPE {metric} summary")
            p = snap[series]
            for q, key in (("0.5", "p50"), ("0.95", "p95"), ("0.99", "p99")):
                lines.append(f'{metric}{{quantile="{q}"}} {p[key]:.3f}')
            lines.append(f"{metric}_count {int(p['n'])}")
        return "\n".join(lines) + "\n"
