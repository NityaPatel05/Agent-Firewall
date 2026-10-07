"""One command for the offline evaluation: scenarios -> mutations -> AgentDojo replay -> benches -> report."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from firewall.settings import get_settings


def _step(name: str, fn: object, *args: object) -> None:
    t0 = time.perf_counter()
    print(f"== {name}", flush=True)
    rc = fn(*args)  # type: ignore[operator]
    print(f"== {name}: rc={rc} ({time.perf_counter() - t0:.0f} s)", flush=True)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m firewall.eval.all")
    p.add_argument("--offline", action="store_true", required=True, help="(the only mode; live runs are explicit)")
    p.add_argument("--run-id", default="final")
    p.add_argument("--out", type=Path, default=None, help="report directory (default reports/<run-id>)")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--skip-agentdojo", action="store_true")
    p.add_argument("--live-runs", nargs="*", type=Path, default=[], help="existing live run dirs to include")
    p.add_argument("--agentdojo-live", nargs="*", type=Path, default=[], help="existing AgentDojo live run dirs")
    args = p.parse_args(argv)
    from firewall.bench import http, latency
    from firewall.eval import mutations, report, run_scenarios

    runs = get_settings().runs_dir
    rid = args.run_id
    rdir = runs / rid
    out = args.out or Path("reports") / rid
    _step("scenario suite", run_scenarios.main, ["--offline", "--run-id", rid, "--approver", "both",
                                                 "--workers", str(args.workers), "--quiet"])
    _step("ablations", run_scenarios.main, ["--offline", "--run-id", f"{rid}-ablations", "--workers",
                                            str(args.workers), "--quiet", "--defenses",
                                            "ABL-PROV,ABL-ROLES,ABL-TASKSPEC,ABL-SINKS,ABL-SCHEMA,ABL-R2,ABL-PIN,GW+D"])
    _step("mutations", mutations.main, ["--offline", "--json", str(rdir / "mutations.json")])
    ad_dirs: list[Path] = []
    if not args.skip_agentdojo:
        try:
            from firewall.eval.agentdojo.compat import require_agentdojo

            require_agentdojo()
            from firewall.eval.agentdojo import run as adrun

            _step("agentdojo replay", adrun.main, ["--replay", "--run-id", f"{rid}-agentdojo"])
            ad_dirs = [runs / f"{rid}-agentdojo"]
        except ImportError as exc:
            print(f"agentdojo replay skipped: {exc}")
    _step("bench latency", latency.main, ["--n", "10000", "--json", str(rdir / "bench_latency.json")])
    _step("bench http", http.main, ["--n", "2000", "--json", str(rdir / "bench_http.json")])
    t0 = time.perf_counter()
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"], capture_output=True,
                          text=True, check=False)
    tail = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    (rdir / "suite.json").write_text(json.dumps({"seconds": round(time.perf_counter() - t0, 1),
                                                 "returncode": proc.returncode, "summary": tail}), encoding="utf-8")
    report_args = ["--runs", str(rdir), "--ablations", str(runs / f"{rid}-ablations"), "--out", str(out),
                   "--bench-latency", str(rdir / "bench_latency.json"), "--bench-http", str(rdir / "bench_http.json"),
                   "--mutations", str(rdir / "mutations.json"), "--suite", str(rdir / "suite.json")]
    if ad_dirs:
        report_args += ["--agentdojo-replay", *map(str, ad_dirs)]
    if args.live_runs:
        report_args += ["--live", *map(str, args.live_runs)]
    if args.agentdojo_live:
        report_args += ["--agentdojo-live", *map(str, args.agentdojo_live)]
    _step("report", report.main, report_args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
