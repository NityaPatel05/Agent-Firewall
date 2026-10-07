"""Developer helper: wall-time per pipeline stage (monkeypatched timers, no profiler overhead)."""

from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Callable
from typing import Any

import firewall.core.gateway as gwmod
import firewall.core.pipeline as pl
from firewall.bench.fixtures import bench_calls, build_bench_session
from firewall.core.gateway import Gateway

TOTALS: dict[str, float] = defaultdict(float)


def wrap(mod: Any, name: str) -> None:
    fn: Callable[..., Any] = getattr(mod, name)

    def inner(*a: Any, **k: Any) -> Any:
        t0 = time.perf_counter_ns()
        try:
            return fn(*a, **k)
        finally:
            TOTALS[name] += time.perf_counter_ns() - t0

    setattr(mod, name, inner)


def main() -> None:
    gw = Gateway.from_config()
    sid = build_bench_session(gw)
    calls = bench_calls()
    for c in calls * 10:
        gw.evaluate(sid, c)
    for name in ("resolve_origin", "classify_destinations", "compute_facts", "evaluate_policy", "sink_findings",
                 "exec_findings", "rule_of_two_finding", "_provenance_findings", "_finish"):
        wrap(pl, name)
    wrap(gwmod, "evaluate_detailed")
    orig_validate = gw.validator.validate_args

    def timed_validate(*a: Any, **k: Any) -> Any:
        t0 = time.perf_counter_ns()
        try:
            return orig_validate(*a, **k)
        finally:
            TOTALS["validate_args"] += time.perf_counter_ns() - t0

    gw.validator.validate_args = timed_validate  # type: ignore[method-assign]
    n = 0
    t0 = time.perf_counter_ns()
    for _ in range(50):
        for c in calls:
            gw.evaluate(sid, c)
            n += 1
    total = time.perf_counter_ns() - t0
    print(f"gateway.evaluate total: {total / n / 1000:.1f} us/call")
    for k, v in sorted(TOTALS.items(), key=lambda kv: -kv[1]):
        print(f"  {k:24s} {v / n / 1000:8.1f} us/call")


if __name__ == "__main__":
    main()
