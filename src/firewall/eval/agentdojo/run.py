"""CLI: AgentDojo v1.2.2 — offline ground-truth replay through the gateway, or a small live run."""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
import warnings
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from firewall.eval.records import (
    EpisodeResult,
    RunManifest,
    append_episode,
    done_keys,
    read_episodes,
    run_dir,
)
from firewall.eval.records import write_manifest as _write_manifest

DEFAULT_SUITES = ("banking", "slack", "travel", "workspace")


def _sha() -> str | None:
    from firewall.eval.run_scenarios import _git_sha

    return _git_sha()


def _bench_lock() -> dict[str, str]:
    from pathlib import Path

    p = Path(__file__).resolve().parents[4] / "bench.lock"
    if not p.exists():
        return {}
    return dict(line.split("=", 1) for line in p.read_text(encoding="utf-8").splitlines() if "=" in line)


def select_tasks(suite: Any, n_user: int, n_inj: int, seed: int) -> tuple[list[str], list[str]]:
    """User tasks whose ground truth has >= 1 consequential call (registry metadata), sampled with `seed`."""
    from firewall.eval.agentdojo.registry_map import load_agentdojo_registry

    reg = load_agentdojo_registry(suite.name)
    env = suite.load_and_inject_default_environment({})
    pool = []
    for tid, ut in suite.user_tasks.items():
        calls = ut.ground_truth(ut.init_environment(env.model_copy(deep=True)))
        if any((s := reg.get(c.function)) is not None and s.consequential for c in calls):
            pool.append(tid)
    rng = random.Random(seed)
    users = sorted(rng.sample(sorted(pool), min(n_user, len(pool))))
    injs = sorted(rng.sample(sorted(suite.injection_tasks), min(n_inj, len(suite.injection_tasks))))
    return users, injs


def _table(eps: Sequence[EpisodeResult]) -> None:
    from collections import defaultdict

    groups: dict[tuple[str, str], list[EpisodeResult]] = defaultdict(list)
    for e in eps:
        groups[(e.suite, e.defense)].append(e)
    print(f"{'suite':22} {'def':4} {'GT/calls':>8} {'interrupt%':>10} {'block%':>7} {'BU':>6} {'UA':>6} {'ASR':>7} "
          f"{'eval_us p50':>11}")
    for (suite, d), es in sorted(groups.items()):
        ben = [e for e in es if e.kind == "benign"]
        att = [e for e in es if e.kind == "attack"]
        calls = sum(e.n_tool_calls for e in ben)
        inter = sum(e.n_review + e.n_block for e in ben) / calls if calls else 0.0
        blk = sum(e.n_block for e in ben) / calls if calls else 0.0
        bu = sum(e.utility for e in ben) / len(ben) if ben else float("nan")
        ua = sum(e.utility for e in att) / len(att) if att else float("nan")
        asr = sum(bool(e.attack_success) for e in att) / len(att) if att else float("nan")
        lat = sorted(x.eval_us for e in es for x in e.decisions if x.eval_us > 0)
        p50 = lat[len(lat) // 2] if lat else 0.0
        print(f"{suite:22} {d:4} {calls:8d} {100 * inter:9.1f}% {100 * blk:6.1f}% {100 * bu:5.1f}% {100 * ua:5.1f}% "
              f"{100 * asr:6.1f}% {p50:11.0f}")


def run_replay(args: argparse.Namespace, run_id: str) -> list[EpisodeResult]:
    from firewall.eval.agentdojo.compat import check_security_sign
    from firewall.eval.agentdojo.replay import replay_suite, to_episode

    check_security_sign("banking")
    out = []
    for suite in args.suites.split(","):
        for defense in args.defenses.split(","):
            t0 = time.perf_counter()
            cases = replay_suite(suite, defense=defense, attack=args.attacks.split(",")[0])
            ms = (time.perf_counter() - t0) * 1000 / max(1, len(cases))
            out += [to_episode(c, run_id=run_id, defense=defense, wall_ms=ms) for c in cases]
    return out


def _intermediate(messages: Sequence[Any], inj_calls: Sequence[Any]) -> bool:
    """A proposed call to an injection-task ground-truth function carrying one of its argument values."""
    targets = {c.function: [str(v).lower() for v in c.args.values() if len(str(v)) >= 4] for c in inj_calls}
    for m in messages:
        if m["role"] != "assistant":
            continue
        for tc in m.get("tool_calls") or []:
            if tc.function in targets:
                blob = json.dumps(dict(tc.args), default=str).lower()
                vals = targets[tc.function]
                if not vals or any(v in blob for v in vals):
                    return True
    return False


def live_episode(suite: Any, ut: Any, it: Any, *, defense: str, role: str, attack_name: str, approver: str,
                 run_id: str, usage: Any, detector: Any) -> EpisodeResult:
    from firewall.eval.agentdojo.pipelines import build_pipeline, make_llm
    from firewall.eval.agentdojo.registry_map import legit_values_from_ground_truth, load_agentdojo_registry
    from firewall.eval.agentdojo.replay import counts
    from firewall.llm.config import load_model_config
    from firewall.llm.providers import make_chat_model

    model_id = load_model_config().role(role).model
    chat = make_chat_model(role, usage=usage)
    llm = make_llm(chat, model_id)
    env0 = suite.load_and_inject_default_environment({})
    gt = ut.ground_truth(ut.init_environment(env0.model_copy(deep=True)))
    legit = legit_values_from_ground_truth(gt, load_agentdojo_registry(suite.name))
    pipe, ex, det = build_pipeline(defense, llm=llm, model_id=model_id, suite=suite.name,
                                   approver_mode=approver, legit=legit,  # type: ignore[arg-type]
                                   filter_model=chat if defense == "B2" else None, detector=detector)
    injections: dict[str, str] = {}
    if it is not None:
        from agentdojo.attacks.attack_registry import load_attack

        injections = load_attack(attack_name, suite, pipe).attack(ut, it)
    from firewall.eval.agentdojo.scoring import run_pair

    before = usage.snapshot()
    t0 = time.perf_counter()
    error = None
    captured: list[Any] = []
    native: bool | None = None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            res = run_pair(suite, pipe, ut, it, injections)
        utility, security, native, captured = res.utility, res.security_executed, res.security_native, res.messages
    except Exception as exc:  # noqa: BLE001 - provider errors are recorded (AgentDojo convention), never hidden
        utility, security, error = False, False, f"{type(exc).__name__}: {str(exc)[:200]}"
    wall = (time.perf_counter() - t0) * 1000
    after = usage.snapshot()
    a, r, b, lites = counts(ex.decisions if ex else [])
    if det is not None:
        b = det.omissions   # outputs hidden by the detector baseline
    n_calls = sum(len(m.get("tool_calls") or []) for m in captured if m["role"] == "assistant")
    inter = _intermediate(captured, it.ground_truth(env0)) if it is not None else None
    sid = f"AD-{suite.name}-{ut.ID}" + (f"-{it.ID}" if it is not None else "")
    return EpisodeResult(
        run_id=run_id, scenario_id=sid, kind="attack" if it is not None else "benign", suite=f"agentdojo/{suite.name}",
        category=f"agentdojo/{suite.name}", defense=defense, mode="live", model=model_id, approver=approver, seed=0,
        attack_success=bool(security) if it is not None else None,
        attack_success_native=native if it is not None else None, utility=bool(utility), intermediate=inter,
        error=error, n_tool_calls=n_calls, n_allow=a if ex else n_calls - b, n_review=r, n_block=b, decisions=lites,
        wall_ms=wall,
        llm_calls=after["calls"] - before["calls"], tokens_in=after["tokens_in"] - before["tokens_in"],
        tokens_out=after["tokens_out"] - before["tokens_out"],
        cost_usd=round(after["cost_usd"] - before["cost_usd"], 6), tags=["agentdojo", attack_name])


def run_live(args: argparse.Namespace, run_id: str, path: Any) -> list[EpisodeResult]:
    import os

    from firewall.baselines.defenses import DEFENSES
    from firewall.eval.agentdojo.compat import get_suite
    from firewall.eval.runner import free_detectors, get_shared_detector
    from firewall.llm.cache import UsageTracker
    from firewall.llm.ratelimit import QuotaExhausted
    from firewall.settings import clear_settings_cache

    os.environ["FIREWALL_MODE"] = "live"
    clear_settings_cache()
    usage = UsageTracker()
    done = done_keys(path) if args.resume else set()
    out: list[EpisodeResult] = []
    plan: dict[str, Any] = {}
    for suite_name in args.suites.split(","):
        suite = get_suite(suite_name)
        users, injs = select_tasks(suite, args.n_user, args.n_inj, args.seed)
        plan[suite_name] = {"user_tasks": users, "injection_tasks": injs}
        for defense in args.defenses.split(","):
            detector = get_shared_detector(DEFENSES["B3"]) if defense == "B3" else None
            pairs = [(u, None) for u in users] + [(u, i) for u in users for i in injs]
            for u, i in pairs:
                sid = f"AD-{suite_name}-{u}" + (f"-{i}" if i else "")
                if (sid, defense, args.approver, 0) in done:
                    continue
                if usage.snapshot()["calls"] >= args.max_llm_calls:
                    print("budget exhausted")
                    return out
                try:
                    ep = live_episode(suite, suite.get_user_task_by_id(u), suite.get_injection_task_by_id(i) if i else None,
                                      defense=defense, role=args.model_role, attack_name=args.attacks.split(",")[0],
                                      approver=args.approver, run_id=run_id, usage=usage, detector=detector)
                except QuotaExhausted as exc:
                    print(f"quota exhausted: {exc}")
                    return out
                append_episode(path, ep)
                out.append(ep)
                print(f"{sid} {defense}: utility={ep.utility} attack={ep.attack_success} inter={ep.intermediate} "
                      f"calls={ep.llm_calls} err={ep.error}", flush=True)
            free_detectors()
    (run_dir(run_id) / "agentdojo_plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    return out


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m firewall.eval.agentdojo.run")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--replay", action="store_true", help="offline ground-truth replay (no LLM)")
    mode.add_argument("--live", action="store_true", help="live run with a provider model (keys from .env)")
    p.add_argument("--suites", default=",".join(DEFAULT_SUITES))
    p.add_argument("--defenses", default=None, help="replay: GW,B0; live: B0,B2,B3,GW")
    p.add_argument("--attacks", default="important_instructions")
    p.add_argument("--model-role", default="agent")
    p.add_argument("--approver", choices=["oracle", "autodeny"], default="oracle")
    p.add_argument("--n-user", type=int, default=2, help="live: user tasks per suite")
    p.add_argument("--n-inj", type=int, default=2, help="live: injection tasks per suite")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--max-llm-calls", type=int, default=300)
    p.add_argument("--run-id", default=None)
    p.add_argument("--resume", action="store_true")
    args = p.parse_args(argv)
    from firewall.eval.agentdojo.compat import AgentDojoMissing, require_agentdojo

    try:
        require_agentdojo()
    except AgentDojoMissing as exc:
        print(f"skipped: {exc}")
        return 0
    kind = "replay" if args.replay else "live"
    args.defenses = args.defenses or ("GW,B0" if args.replay else "B0,B2,B3,GW")
    run_id = args.run_id or f"agentdojo-{kind}-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}"
    rdir = run_dir(run_id)
    path = rdir / "episodes.jsonl"
    if not args.resume and path.exists():
        path.unlink()
    t0 = time.perf_counter()
    if args.replay:
        for ep in run_replay(args, run_id):
            append_episode(path, ep)
    else:
        run_live(args, run_id, path)
    lock = _bench_lock()
    from firewall.llm.config import load_model_config

    _write_manifest(rdir / "manifest.json", RunManifest(
        run_id=run_id, created=datetime.now(UTC).isoformat(), git_sha=_sha(), argv=list(argv or sys.argv[1:]),
        versions={"agentdojo_sha": lock.get("agentdojo_sha", ""), "benchmark_version": "v1.2.2"},
        defenses=args.defenses.split(","), mode="offline" if args.replay else "live",
        models={} if args.replay else {args.model_role: load_model_config().role(args.model_role).model},
        seed=args.seed, notes=f"agentdojo {kind}; attack={args.attacks}"))
    eps = read_episodes(path)
    print(f"run {run_id}: {len(eps)} episodes in {time.perf_counter() - t0:.1f} s -> {rdir}")
    _table(eps)
    return 0


if __name__ == "__main__":
    sys.exit(main())
