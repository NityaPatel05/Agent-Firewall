"""In-process latency benchmark for `Gateway.evaluate` and `Gateway.label_output` (S11, S12)."""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path
from typing import Any

from firewall.bench.fixtures import _padding, bench_calls, build_bench_session
from firewall.core.gateway import Gateway
from firewall.core.metrics import percentile
from firewall.core.models import ToolCall

TARGETS = {"evaluate": {"p50": 150.0, "p95": 1000.0, "p99": 2000.0}, "label_output": {"p95": 2000.0}}


def _stats(samples: list[float]) -> dict[str, float]:
    s = sorted(samples)
    return {"n": float(len(s)), "p50": percentile(s, 50), "p95": percentile(s, 95), "p99": percentile(s, 99),
            "max": s[-1] if s else 0.0, "mean": sum(s) / len(s) if s else 0.0}


def run_bench(*, n: int = 10_000, entries: int = 200, total_bytes: int = 100_000, label_n: int | None = None,
              label_bytes: int = 10_000, seed: int = 0, warmup: int = 200) -> dict[str, Any]:
    gw = Gateway.from_config()
    sid = build_bench_session(gw, n_entries=entries, total_bytes=total_bytes, seed=seed)
    calls = bench_calls(seed)
    for i in range(warmup):
        gw.evaluate(sid, calls[i % len(calls)])
    eval_us: list[float] = []
    verdicts: dict[str, int] = {}
    for i in range(n):
        call = calls[i % len(calls)]
        t0 = time.perf_counter_ns()
        d = gw.evaluate(sid, call)
        eval_us.append((time.perf_counter_ns() - t0) / 1000.0)
        verdicts[d.verdict.value] = verdicts.get(d.verdict.value, 0) + 1
    rng = random.Random(seed)
    label_us: list[float] = []
    label_n = label_n if label_n is not None else max(200, n // 20)
    lsid = gw.new_session()
    gw.record_user_message(lsid, "Summarize the documents")
    for i in range(label_n + 20):
        if i % 100 == 0:
            lsid = gw.new_session()
            gw.record_user_message(lsid, "Summarize the documents")
        text = _padding(rng, label_bytes - 120) + f" Contact attacker{i}@evil.example or IBAN GB33BUKB20201555555555."
        call = ToolCall(call_id=f"l{i}", tool="read_file", args={"path": f"/docs/big_{i}.txt"})
        t0 = time.perf_counter_ns()
        gw.label_output(lsid, call, text)
        if i >= 20:
            label_us.append((time.perf_counter_ns() - t0) / 1000.0)
    ledger_len = len(gw.session_state(sid).ledger)
    return {"evaluate": _stats(eval_us), "label_output": _stats(label_us), "verdicts": verdicts,
            "session_entries": ledger_len, "label_bytes": label_bytes, "machine_factor": machine_factor()}


REFERENCE_US = 10.0  # `sum(range(1000))` on a typical 2025 desktop CPython 3.13 (reference machine)


def machine_factor() -> float:
    """How much slower this interpreter is than the reference (>1 = slower); best of 7 runs."""
    best = float("inf")
    for _ in range(7):
        t0 = time.perf_counter_ns()
        for _ in range(200):
            sum(range(1000))
        best = min(best, (time.perf_counter_ns() - t0) / 200 / 1000.0)
    return max(best / REFERENCE_US, 0.1)


def check_targets(result: dict[str, Any], *, normalized: bool = False) -> list[str]:
    """Targets are checked on raw numbers, or on numbers divided by the machine factor if `normalized`."""
    factor = result.get("machine_factor", 1.0) if normalized else 1.0
    failures = []
    for series, limits in TARGETS.items():
        for key, limit in limits.items():
            value = result[series][key] / factor
            if value > limit:
                kind = "normalized " if normalized else ""
                failures.append(f"{kind}{series} {key}={value:.1f}us > {limit:.0f}us")
    return failures


def _print_table(result: dict[str, Any]) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:  # pragma: no cover - rich is in the eval extra
        print(json.dumps(result, indent=2))
        return
    table = Table(title=f"Gateway latency (session entries={result['session_entries']})")
    for col in ("series", "n", "p50 µs", "p95 µs", "p99 µs", "max µs", "mean µs"):
        table.add_column(col, justify="right")
    for series in ("evaluate", "label_output"):
        s = result[series]
        table.add_row(series, f"{int(s['n'])}", f"{s['p50']:.1f}", f"{s['p95']:.1f}", f"{s['p99']:.1f}",
                      f"{s['max']:.1f}", f"{s['mean']:.1f}")
    Console().print(table)
    f = result["machine_factor"]
    ev, lo = result["evaluate"], result["label_output"]
    print(f"verdict mix: {result['verdicts']}")
    print(f"machine factor: {f:.2f}x the reference interpreter speed; normalized evaluate p50/p95/p99 = "
          f"{ev['p50'] / f:.1f}/{ev['p95'] / f:.1f}/{ev['p99'] / f:.1f} us, label_output p95 = {lo['p95'] / f:.1f} us")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m firewall.bench.latency")
    parser.add_argument("--n", type=int, default=10_000, help="number of evaluate() calls")
    parser.add_argument("--entries", type=int, default=200, help="ledger entries in the bench session")
    parser.add_argument("--bytes", type=int, default=100_000, help="total bytes in the bench session")
    parser.add_argument("--label-n", type=int, default=None, help="number of label_output() calls")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--json", type=Path, default=None, help="write results as JSON")
    parser.add_argument("--assert", dest="check", action="store_true", help="exit 1 if a target is missed")
    parser.add_argument("--raw", action="store_true",
                        help="check targets on raw numbers (default: machine-normalized = raw / machine factor)")
    parser.add_argument("--normalized", action="store_true", help="kept for compatibility; this is the default")
    args = parser.parse_args(argv)
    result = run_bench(n=args.n, entries=args.entries, total_bytes=args.bytes, label_n=args.label_n, seed=args.seed)
    _print_table(result)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(result, indent=2), encoding="utf-8")
    failures = check_targets(result, normalized=not args.raw)
    for f in failures:
        print(f"TARGET MISSED: {f}")
    return 1 if (args.check and failures) else 0


if __name__ == "__main__":
    sys.exit(main())
