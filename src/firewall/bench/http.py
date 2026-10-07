"""HTTP round-trip latency of `POST /v1/tool-calls:evaluate` on localhost (S13)."""

from __future__ import annotations

import argparse
import json
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Self

from firewall.bench.fixtures import bench_calls, build_bench_session
from firewall.bench.latency import machine_factor
from firewall.core.metrics import percentile

TARGETS_MS = {"p50": 3.0, "p95": 10.0}


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class BackgroundServer:
    """uvicorn serving `create_app()` in a daemon thread."""

    def __init__(self, port: int | None = None, audit_dir: Path | None = None) -> None:
        import uvicorn

        from firewall.service.app import create_app

        self.port = port or _free_port()
        self._tmp = tempfile.TemporaryDirectory() if audit_dir is None else None
        audit = (Path(self._tmp.name) if self._tmp else audit_dir) / "audit.jsonl"  # type: ignore[operator]
        config = uvicorn.Config(create_app(audit_path=audit), host="127.0.0.1", port=self.port, loop="asyncio",
                                log_level="warning", lifespan="on")
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, name="fw-bench-http", daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> Self:
        self.thread.start()
        deadline = time.monotonic() + 30
        while not self.server.started:
            if time.monotonic() > deadline or not self.thread.is_alive():
                raise RuntimeError("uvicorn did not start")
            time.sleep(0.05)
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)
        if self._tmp is not None:
            self._tmp.cleanup()


def run_http_bench(*, n: int = 2000, warmup: int = 100, entries: int = 200, total_bytes: int = 100_000,
                   seed: int = 0) -> dict[str, Any]:
    from firewall.service.client import RemoteGateway

    with BackgroundServer() as srv:
        gw = RemoteGateway(srv.base_url, timeout=30.0)
        try:
            sid = build_bench_session(gw, n_entries=entries, total_bytes=total_bytes, seed=seed)
            calls = bench_calls(seed)
            for i in range(warmup):
                gw.evaluate(sid, calls[i % len(calls)])
            samples: list[float] = []
            for i in range(n):
                t0 = time.perf_counter()
                gw.evaluate(sid, calls[i % len(calls)])
                samples.append((time.perf_counter() - t0) * 1000.0)
        finally:
            gw.close()
    s = sorted(samples)
    stats = {"n": float(len(s)), "p50": percentile(s, 50), "p95": percentile(s, 95), "p99": percentile(s, 99),
             "max": s[-1], "mean": sum(s) / len(s)}
    return {"evaluate_http_ms": stats, "machine_factor": machine_factor()}


def check(result: dict[str, Any], *, normalized: bool = True) -> list[str]:
    factor = result["machine_factor"] if normalized else 1.0
    out = []
    for key, limit in TARGETS_MS.items():
        value = result["evaluate_http_ms"][key] / factor
        if value > limit:
            out.append(f"{'normalized ' if normalized else ''}HTTP {key}={value:.2f}ms > {limit}ms")
    return out


def _print(result: dict[str, Any]) -> None:
    s, f = result["evaluate_http_ms"], result["machine_factor"]
    try:
        from rich.console import Console
        from rich.table import Table

        table = Table(title="HTTP round trip POST /v1/tool-calls:evaluate (localhost, keep-alive)")
        for col in ("n", "p50 ms", "p95 ms", "p99 ms", "max ms", "mean ms"):
            table.add_column(col, justify="right")
        table.add_row(f"{int(s['n'])}", f"{s['p50']:.2f}", f"{s['p95']:.2f}", f"{s['p99']:.2f}", f"{s['max']:.2f}",
                      f"{s['mean']:.2f}")
        Console().print(table)
    except ImportError:  # pragma: no cover
        print(json.dumps(s, indent=2))
    print(f"machine factor: {f:.2f}x; normalized p50/p95/p99 = {s['p50'] / f:.2f}/{s['p95'] / f:.2f}/"
          f"{s['p99'] / f:.2f} ms (targets p50 <= 3 ms, p95 <= 10 ms)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m firewall.bench.http")
    parser.add_argument("--n", type=int, default=2000, help="number of evaluate round trips")
    parser.add_argument("--json", type=Path, default=None, help="write results as JSON")
    parser.add_argument("--assert", dest="check", action="store_true",
                        help="exit 1 if p50 > 3 ms or p95 > 10 ms (machine-normalized unless --raw)")
    parser.add_argument("--raw", action="store_true", help="check raw instead of machine-normalized numbers")
    args = parser.parse_args(argv)
    result = run_http_bench(n=args.n)
    _print(result)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(result, indent=2), encoding="utf-8")
    failures = check(result, normalized=not args.raw)
    for f in failures:
        print(f"TARGET MISSED: {f}")
    return 1 if (args.check and failures) else 0


if __name__ == "__main__":
    sys.exit(main())
