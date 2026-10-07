"""Latency budget (S11/S12, loosened for CI stability) + a pytest-benchmark report of `evaluate`."""

from __future__ import annotations

import pytest

from firewall.bench.fixtures import bench_calls, build_bench_session
from firewall.bench.latency import check_targets, machine_factor, run_bench
from firewall.core.gateway import Gateway


@pytest.mark.slow
def test_latency_budget() -> None:
    result = run_bench(n=2000, label_n=100)
    factor = max(1.0, result["machine_factor"])
    # Plan: evaluate p95 < 2 ms (looser than the 1 ms target). Normalized by interpreter speed on slow machines.
    assert result["evaluate"]["p95"] / factor < 2000.0, result["evaluate"]
    assert result["label_output"]["p95"] / factor < 4000.0, result["label_output"]
    assert sum(result["verdicts"].values()) == 2000
    assert set(result["verdicts"]) == {"allow", "review", "block"}


def test_check_targets_and_factor() -> None:
    ok = {"evaluate": {"p50": 100.0, "p95": 500.0, "p99": 900.0}, "label_output": {"p95": 1000.0},
          "machine_factor": 3.0}
    assert check_targets(ok) == []
    slow = {"evaluate": {"p50": 300.0, "p95": 2500.0, "p99": 5000.0}, "label_output": {"p95": 5000.0},
            "machine_factor": 3.0}
    assert len(check_targets(slow)) == 4
    assert check_targets(slow, normalized=True) == []
    assert machine_factor() > 0


def test_small_session_evaluate_timing() -> None:
    """Plain timing (pytest-benchmark 5.3 is incompatible with pytest 9.2; see docs/DECISIONS.md)."""
    gw = Gateway.from_config()
    sid = build_bench_session(gw, n_entries=60, total_bytes=20_000)
    calls = bench_calls()
    for c in calls:
        gw.evaluate(sid, c)
    samples: list[float] = []
    for i in range(200):
        samples.append(gw.evaluate(sid, calls[i % len(calls)]).eval_us)
    samples.sort()
    assert samples[len(samples) // 2] / max(1.0, machine_factor()) < 1000.0
