"""Smoke test of the HTTP bench: real uvicorn on a loopback port (allowed by the offline network guard)."""

from __future__ import annotations

import pytest

from firewall.bench.http import check, run_http_bench


@pytest.mark.slow
def test_http_bench_smoke() -> None:
    result = run_http_bench(n=30, warmup=5, entries=20, total_bytes=5_000)
    s = result["evaluate_http_ms"]
    assert s["n"] == 30 and 0 < s["p50"] <= s["p95"] <= s["max"]
    assert result["machine_factor"] > 0


def test_check_normalized_vs_raw() -> None:
    r = {"evaluate_http_ms": {"p50": 5.0, "p95": 8.0}, "machine_factor": 2.5}
    assert check(r) == []
    assert check(r, normalized=False) == ["HTTP p50=5.00ms > 3.0ms"]
