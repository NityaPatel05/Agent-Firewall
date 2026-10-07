"""Developer profiling helper (not part of the package): cProfile evaluate() and label_output()."""

from __future__ import annotations

import cProfile
import pstats
import random
import sys
import time

from firewall.bench.fixtures import _padding, bench_calls, build_bench_session
from firewall.core.gateway import Gateway
from firewall.core.models import ToolCall


def main() -> None:
    what = sys.argv[1] if len(sys.argv) > 1 else "evaluate"
    gw = Gateway.from_config()
    sid = build_bench_session(gw)
    calls = bench_calls()
    for c in calls * 10:
        gw.evaluate(sid, c)
    if what == "per-call":
        for c in calls:
            t0 = time.perf_counter_ns()
            for _ in range(50):
                gw.evaluate(sid, c)
            print(f"{(time.perf_counter_ns() - t0) / 50_000:8.1f}us  {c.tool} {list(c.args)[:2]}")
        return
    pr = cProfile.Profile()
    if what == "evaluate":
        pr.enable()
        for _ in range(20):
            for c in calls:
                gw.evaluate(sid, c)
        pr.disable()
    else:
        rng = random.Random(0)
        lsid = gw.new_session()
        texts = [_padding(rng, 9900) + " attacker@evil.example" for _ in range(60)]
        pr.enable()
        for i, t in enumerate(texts):
            gw.label_output(lsid, ToolCall(call_id=f"l{i}", tool="read_file", args={"path": f"/d/{i}.txt"}), t)
        pr.disable()
    pstats.Stats(pr).sort_stats("tottime").print_stats(22)


if __name__ == "__main__":
    main()
