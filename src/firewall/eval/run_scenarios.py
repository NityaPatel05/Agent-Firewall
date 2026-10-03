"""CLI: run the scenario suite under several defenses (offline scripted, or live/replay) and print metrics."""

from __future__ import annotations

import argparse
import csv
import json
import random
import subprocess
import sys
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from firewall.baselines.defenses import DEFENSES
from firewall.core.audit import JsonlAuditSink
from firewall.eval.loader import load_scenarios
from firewall.eval.metrics import MetricRow, compute_metrics
from firewall.eval.parallel import run_parallel
from firewall.eval.records import (
    EpisodeResult,
    RunManifest,
    append_episode,
    done_keys,
    read_episodes,
    run_dir,
    write_manifest,
)
from firewall.eval.runner import RunConfig, free_detectors, run_scenario
from firewall.eval.scenario import Scenario
from firewall.llm.cache import UsageTracker
from firewall.llm.ratelimit import QuotaExhausted

OFFLINE_DEFAULT = ["GW", "GW-STRICT", "B0", "B2", "B6"]
_HF_MODELS = {"B3": "protectai/deberta-v3-base-prompt-injection-v2", "B3c": "protectai/deberta-v3-base-prompt-injection-v2",
              "B4": "meta-llama/Llama-Prompt-Guard-2-86M", "B4c": "meta-llama/Llama-Prompt-Guard-2-86M",
              "B4s": "meta-llama/Llama-Prompt-Guard-2-22M"}


def weights_present(defense: str) -> bool:
    repo = _HF_MODELS.get(defense)
    if repo is None:
        return True
    try:
        from huggingface_hub import try_to_load_from_cache
    except ImportError:
        return False
    hit = try_to_load_from_cache(repo, "config.json")
    return isinstance(hit, str)


def select_subset(scenarios: list[Scenario], name: str, seed: int) -> list[Scenario]:
    """`mini` = 10 A + 10 B (twins first) + 4 LP + 10 PB; `dev` = all A/B + 12 LP + 30 PB; `full` = all."""
    if name == "full":
        return scenarios
    rng = random.Random(seed)
    a = [s for s in scenarios if s.id[0] == "A" and s.id[1:].isdigit()]
    b = {s.id: s for s in scenarios if s.id[0] == "B" and s.id[1:].isdigit()}
    lp = [s for s in scenarios if s.id.startswith("LP-")]
    pb = [s for s in scenarios if s.id.startswith("PB-")]
    if name == "dev":
        return [*a, *b.values(), *rng.sample(lp, min(12, len(lp))), *rng.sample(pb, min(30, len(pb)))]
    twins = [s for s in a if s.twin in b]
    rest = [s for s in a if s.twin not in b]
    pick_a = (twins + rng.sample(rest, len(rest)))[:10]
    pick_b = [b[s.twin] for s in pick_a if s.twin in b]
    others = [x for k, x in sorted(b.items()) if x not in pick_b]
    pick_b += rng.sample(others, max(0, 10 - len(pick_b)))
    return [*pick_a, *pick_b, *rng.sample(lp, min(4, len(lp))), *rng.sample(pb, min(10, len(pb)))]


def _git_sha() -> str | None:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5, check=False)
    except OSError:
        return None
    sha = out.stdout.strip()
    return sha if len(sha) == 40 and all(c in "0123456789abcdef" for c in sha) else None   # None: no commits yet


def _versions() -> dict[str, str]:
    from importlib.metadata import PackageNotFoundError, version

    out = {"python": sys.version.split()[0]}
    for pkg in ("langchain", "langgraph", "langchain-google-genai", "langchain-groq", "pydantic"):
        try:
            out[pkg] = version(pkg)
        except PackageNotFoundError:
            pass
    return out


def _fmt(v: float | None, pct: bool = True) -> str:
    if v is None:
        return "-"
    return f"{100 * v:.1f}%" if pct else f"{v:.0f}"


def _ci(ci: tuple[float, float] | None) -> str:
    return "" if ci is None else f" [{100 * ci[0]:.0f}-{100 * ci[1]:.0f}]"


TABLE_COLS = ("defense", "approver", "ASR [CI]", "inter. ASR", "UA", "BU [CI]", "interrupt", "review", "block",
              "derail", "twin-sep", "eval µs p50/p95", "LLM calls", "cost $")


def table_rows(rows: Sequence[MetricRow]) -> list[list[str]]:
    return [[r.group.get("defense", ""), r.group.get("approver", ""), _fmt(r.asr) + _ci(r.asr_ci),
             _fmt(r.intermediate_asr), _fmt(r.ua), _fmt(r.bu) + _ci(r.bu_ci), _fmt(r.interruption_rate),
             _fmt(r.review_rate), _fmt(r.block_rate), _fmt(r.derail_rate), _fmt(r.twin_separation),
             f"{_fmt(r.eval_us_p50, False)}/{_fmt(r.eval_us_p95, False)}", str(r.llm_calls), f"{r.cost_usd:.4f}"]
            for r in rows]


def print_tables(eps: Sequence[EpisodeResult]) -> dict[str, list[MetricRow]]:
    out: dict[str, list[MetricRow]] = {}
    for subset in ("A", "B", "LP", "PB", "T"):
        rows = compute_metrics(eps, group_by=("defense", "approver"), subset=subset)  # type: ignore[arg-type]
        if not rows:
            continue
        out[subset] = rows
        try:
            from rich.console import Console
            from rich.table import Table

            t = Table(title=f"subset {subset}")
            for c in TABLE_COLS:
                t.add_column(c)
            for r in table_rows(rows):
                t.add_row(*r)
            Console(width=200).print(t)
        except ImportError:  # pragma: no cover
            print(f"== subset {subset}")
            for r in table_rows(rows):
                print(" | ".join(r))
    return out


def export_results(eps: Sequence[EpisodeResult], tables: dict[str, list[MetricRow]], dest: Path,
                   run_id: str) -> None:
    """CSV/JSON summaries + per-episode CSV (no secrets: scenario data only)."""
    dest.mkdir(parents=True, exist_ok=True)
    summary = [{"subset": s, **r.group, **r.model_dump(exclude={"group"})} for s, rows in tables.items()
               for r in rows]
    (dest / f"{run_id}_summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    if summary:
        with (dest / f"{run_id}_summary.csv").open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(summary[0]))
            w.writeheader()
            w.writerows({k: (json.dumps(v) if isinstance(v, (list, tuple, dict)) else v) for k, v in row.items()}
                        for row in summary)
    cols = ["scenario_id", "kind", "suite", "category", "defense", "approver", "mode", "model", "attack_success",
            "utility", "intermediate", "error", "n_tool_calls", "n_allow", "n_review", "n_block",
            "n_review_approved", "n_omitted", "wall_ms", "llm_calls", "tokens_in", "tokens_out", "cost_usd"]
    with (dest / f"{run_id}_episodes.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=[*cols, "rule_ids"])
        w.writeheader()
        for e in eps:
            row: dict[str, Any] = {c: getattr(e, c) for c in cols}
            row["rule_ids"] = ";".join(sorted({r for d in e.decisions for r in d.rule_ids}))
            w.writerow(row)


def _parse(argv: Sequence[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="python -m firewall.eval.run_scenarios")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--offline", action="store_true", help="scripted compromised/benign trajectories (default)")
    mode.add_argument("--live", action="store_true", help="real provider model (keys from .env; cached)")
    mode.add_argument("--replay", action="store_true", help="cached responses only")
    p.add_argument("--defenses", default=None)
    p.add_argument("--kinds", default=None)
    p.add_argument("--include", default="core,extra,livepi,pinch")
    p.add_argument("--ids", default=None)
    p.add_argument("--suites", default=None)
    p.add_argument("--approver", choices=["oracle", "autodeny", "both"], default="oracle")
    p.add_argument("--run-id", default=None)
    p.add_argument("--resume", action="store_true")
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--planner", choices=["rule", "llm", "fixture"], default="rule")
    p.add_argument("--workers", type=int, default=1)
    p.add_argument("--subset", choices=["mini", "dev", "full"], default=None)
    p.add_argument("--agent-role", default="agent")
    p.add_argument("--live-tools", choices=["all", "script"], default="all",
                   help="live: bind all tool families or only the scenario script's (small-TPM providers)")
    p.add_argument("--system-prompt", choices=["default", "neutral"], default="default",
                   help="'neutral' drops the agent prompt's one-line injection warning (no prompt-level defense)")
    p.add_argument("--max-llm-calls", type=int, default=400)
    p.add_argument("--results-dir", type=Path, default=None, help="also export CSV/JSON summaries here")
    p.add_argument("--quiet", action="store_true", help="no tables")
    return p.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse(argv)
    mode = "live" if args.live else "replay" if args.replay else "offline"
    if mode != "offline":
        import os

        os.environ["FIREWALL_MODE"] = mode
        from firewall.settings import clear_settings_cache

        clear_settings_cache()
    defenses = args.defenses.split(",") if args.defenses else (OFFLINE_DEFAULT + ["B3", "B4"] if mode == "offline"
                                                               else ["GW", "B0"])
    runnable: list[str] = []
    for d in defenses:
        cfg = DEFENSES[d]
        if mode == "offline" and cfg.live_only:
            print(f"skipped {d}: live only")
        elif cfg.needs_models and not weights_present(d):
            print(f"skipped {d}: weights not present (gated or not downloaded)")
        else:
            runnable.append(d)
    scenarios = load_scenarios(kinds=args.kinds.split(",") if args.kinds else None,
                               suites=args.suites.split(",") if args.suites else None,
                               ids=args.ids.split(",") if args.ids else None,
                               include=tuple(args.include.split(",")), seed=args.seed)  # type: ignore[arg-type]
    if args.subset:
        scenarios = select_subset(scenarios, args.subset, args.seed)
    if args.limit:
        scenarios = scenarios[: args.limit]
    approvers = ["oracle", "autodeny"] if args.approver == "both" else [args.approver]
    run_id = args.run_id or f"{mode}-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}"
    rdir = run_dir(run_id)
    ep_path = rdir / "episodes.jsonl"
    done = done_keys(ep_path) if args.resume else set()
    if not args.resume and ep_path.exists():
        ep_path.unlink()
    from firewall.core.gateway import Gateway
    from firewall.llm.config import load_model_config

    gw0 = Gateway.from_config()
    models = {} if mode == "offline" else {r: s.model for r, s in load_model_config().roles.items()
                                           if r in (args.agent_role, "planner", "judge")}
    manifest = RunManifest(run_id=run_id, created=datetime.now(UTC).isoformat(), git_sha=_git_sha(),
                           policy_hash=gw0.policy.hash, registry_hash=gw0.registry.registry_hash(),
                           argv=list(sys.argv[1:] if argv is None else argv), versions=_versions(),
                           defenses=runnable, mode=mode, models=models, seed=args.seed)
    audit = JsonlAuditSink(rdir / "audit.jsonl")
    usage = UsageTracker()
    notes: list[str] = []
    t0 = time.perf_counter()
    try:
        for defense in runnable:   # one defense at a time: HF detectors are loaded once and freed after
            jobs = [(sc, RunConfig(run_id=run_id, mode=mode, defense=defense, approver=ap,  # type: ignore[arg-type]
                                   agent_role=args.agent_role, planner=args.planner, seed=args.seed,
                                   live_tools=args.live_tools, system_prompt=args.system_prompt))
                    for sc in scenarios for ap in approvers if (sc.id, defense, ap, args.seed) not in done]
            if mode == "offline" and args.workers > 1 and not DEFENSES[defense].needs_models:
                for ep in run_parallel([(sc.id, cfg) for sc, cfg in jobs], include=args.include.split(","),
                                       seed=args.seed, workers=args.workers, audit_dir=str(rdir)):
                    append_episode(ep_path, ep)
            elif mode == "offline" and args.workers > 1:   # one shared HF model, serialized scoring
                with ThreadPoolExecutor(max_workers=args.workers) as pool:
                    for ep in pool.map(lambda j: run_scenario(j[0], j[1], audit=audit), jobs):
                        append_episode(ep_path, ep)
            else:
                for sc, cfg in jobs:
                    if mode != "offline" and usage.snapshot()["calls"] >= args.max_llm_calls:
                        notes.append("budget exhausted")
                        break
                    try:
                        ep = run_scenario(sc, cfg, audit=audit, usage=usage)
                    except QuotaExhausted as exc:
                        notes.append(f"quota exhausted: {exc}")
                        break
                    append_episode(ep_path, ep)
                    if mode != "offline":
                        print(f"{sc.id} {defense}/{cfg.approver}: attack={ep.attack_success} utility={ep.utility} "
                              f"calls={ep.llm_calls} err={ep.error}", flush=True)
            free_detectors()
            if notes:
                break
    finally:
        audit.close()
    manifest.notes = "; ".join(dict.fromkeys(notes))
    write_manifest(rdir / "manifest.json", manifest)
    eps = read_episodes(ep_path)
    print(f"run {run_id}: {len(eps)} episodes in {time.perf_counter() - t0:.1f} s -> {rdir}")
    tables = {} if args.quiet else print_tables(eps)
    if args.results_dir is not None:
        export_results(eps, tables or {s: compute_metrics(eps, group_by=("defense", "approver"), subset=s)
                                       for s in ("A", "B", "LP", "PB", "T")}, args.results_dir, run_id)
        print(f"exported summaries to {args.results_dir}")
    if notes:
        print("notes:", manifest.notes)
    return 0


if __name__ == "__main__":
    sys.exit(main())
